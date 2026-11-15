"""LLM security review of the in-scope files (modes: llm, hybrid).

Defensive use only: reviews the cloned, intentionally vulnerable target and
asks for remediation, never exploits.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from rich.console import Console

from .common import (RESULTS_DIR, SCOPE_FILES, TARGET_DIR, clean_finding, load_dotenv,
                     read_json, validate_finding, write_json)
from .cost import CostTracker, load_prices, write_run

CHUNK_LINES = 150
CHUNK_OVERLAP = 20
MAX_TOKENS = 16000
SEMGREP_PATH = RESULTS_DIR / "semgrep_findings.json"

SYSTEM_PROMPT = """You are a defensive application-security code reviewer. You are reviewing source \
code from an intentionally vulnerable training application so its weaknesses can be documented and fixed.

Report only vulnerabilities you can point to in the code shown. For each one give the weakness, why it is \
exploitable in principle, and a concrete remediation. Do not write exploit payloads or attack steps.

Respond with JSON only, no prose and no markdown fences, in exactly this shape:
{"findings": [{"file": "<path as given>", "line_start": <int>, "line_end": <int>, "cwe": "CWE-<number>", \
"severity": "low|medium|high|critical", "explanation": "<what is wrong and why>", \
"suggested_fix": "<how to remediate>"SOURCE_FIELD}]}

Rules:
- Line numbers are the numbers printed at the start of each code line; stay within the lines shown.
- Use the most specific CWE that fits. One finding per distinct weakness; keep the line range tight.
- If there are no vulnerabilities, return {"findings": []}."""

SOURCE_FIELD = ', "source": "semgrep_confirmed|llm_only"'

HINT_PREAMBLE = """Static analysis hints (from Semgrep) for this chunk. These hints may be wrong or \
incomplete: confirm the ones that are real, reject the ones that are not by leaving them out, and extend \
them with anything the tool missed. Set "source" to "semgrep_confirmed" for a finding that confirms a \
hint and "llm_only" for a finding no hint covers."""


def chunk_lines(lines: list[str], size: int = CHUNK_LINES, overlap: int = CHUNK_OVERLAP) -> list[dict]:
    """Split into chunks of `size` lines sharing `overlap` lines. Lines are 1-based inclusive."""
    if size <= 0 or overlap < 0 or overlap >= size:
        raise ValueError("need size > 0 and 0 <= overlap < size")
    chunks, start, n = [], 0, len(lines)
    while start < n:
        end = min(start + size, n)
        chunks.append({"start": start + 1, "end": end, "lines": lines[start:end]})
        if end == n:
            break
        start = end - overlap
    return chunks


def hints_for_chunk(semgrep_findings: list[dict], file: str, start: int, end: int) -> list[dict]:
    """Semgrep findings for `file` whose line range overlaps [start, end]."""
    return [f for f in semgrep_findings
            if f["file"] == file and f["line_start"] <= end and f["line_end"] >= start]


def build_system(mode: str) -> str:
    return SYSTEM_PROMPT.replace("SOURCE_FIELD", SOURCE_FIELD if mode == "hybrid" else "")


def build_user_prompt(file: str, chunk: dict, hints: list[dict] | None = None) -> str:
    numbered = "\n".join(f"{chunk['start'] + i}: {line}" for i, line in enumerate(chunk["lines"]))
    parts = [f"File: {file} (lines {chunk['start']}-{chunk['end']})", "```", numbered, "```"]
    if hints is not None:
        parts.append(HINT_PREAMBLE)
        if hints:
            parts.extend(f"- lines {h['line_start']}-{h['line_end']}, {h['cwe']}, "
                         f"rule {h.get('rule_id', 'n/a')}: {h['explanation']}" for h in hints)
        else:
            parts.append("- (Semgrep reported nothing for this chunk; that does not mean it is clean.)")
    return "\n".join(parts)


def parse_findings(text: str, file: str, chunk: dict, mode: str) -> list[dict]:
    """Parse and validate model output. Raises ValueError describing the problem."""
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError('top level must be {"findings": [...]}')
    out = []
    for i, finding in enumerate(data["findings"]):
        if isinstance(finding, dict):
            finding = {**finding, "file": file}  # the reviewed file is authoritative
        errors = validate_finding(finding, require_source=(mode == "hybrid"),
                                  line_range=(chunk["start"], chunk["end"]))
        if errors:
            raise ValueError(f"finding {i}: " + "; ".join(errors))
        out.append(clean_finding(finding))
    return out


def review_chunk(client, tracker: CostTracker, model: str, mode: str, file: str,
                 chunk: dict, hints: list[dict] | None) -> tuple[list[dict], str | None]:
    """One chunk -> findings. Retries once on malformed output. Returns (findings, error)."""
    prompt = build_user_prompt(file, chunk, hints)
    error = None
    for attempt in range(2):
        content = prompt if attempt == 0 else (
            f"{prompt}\n\nYour previous reply was rejected ({error}). Reply again with valid JSON only.")
        response = tracker.call(client, file, model=model, max_tokens=MAX_TOKENS,
                                system=build_system(mode), messages=[{"role": "user", "content": content}])
        if response.stop_reason == "refusal":
            return [], "model refused the request"
        text = "".join(b.text for b in response.content if b.type == "text")
        try:
            return parse_findings(text, file, chunk, mode), None
        except ValueError as exc:
            error = str(exc) if response.stop_reason != "max_tokens" else "output truncated at max_tokens"
    return [], f"malformed output after retry: {error}"


def dedupe(findings: list[dict]) -> list[dict]:
    """Drop repeats from overlapping chunks (same file and CWE, overlapping lines)."""
    kept: list[dict] = []
    for f in findings:
        if not any(k["file"] == f["file"] and k["cwe"] == f["cwe"]
                   and k["line_start"] <= f["line_end"] and k["line_end"] >= f["line_start"] for k in kept):
            kept.append(f)
    return kept


def plan(files: list[str], target_dir: Path = TARGET_DIR) -> list[tuple[str, dict]]:
    return [(file, chunk) for file in files
            for chunk in chunk_lines((target_dir / file).read_text().splitlines())]


def main(argv=None) -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["llm", "hybrid"], required=True)
    parser.add_argument("--model", default=os.environ.get("REVIEW_MODEL"),
                        help="model ID (or set REVIEW_MODEL); there is no built-in default")
    parser.add_argument("--files", nargs="*", default=SCOPE_FILES,
                        help="paths relative to ./target (default: built-in scope)")
    parser.add_argument("--dry-run", action="store_true", help="print the call plan, make no API calls")
    args = parser.parse_args(argv)
    console = Console()

    for f in args.files:
        resolved = (TARGET_DIR / f).resolve()
        if not resolved.is_file() or TARGET_DIR.resolve() not in resolved.parents:
            console.print(f"[red]Refusing {f}: only files inside {TARGET_DIR} are reviewed.[/red]")
            return 2
    work = plan(args.files)
    if args.dry_run:
        console.print(f"{len(args.files)} files, {len(work)} chunks -> {len(work)} API calls "
                      f"(max {2 * len(work)} with retries). No calls made.")
        return 0
    if not args.model:
        console.print("[red]No model set. Pass --model or set REVIEW_MODEL.[/red]")
        return 2
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        console.print("[red]ANTHROPIC_API_KEY is not set. Nothing was sent.[/red]")
        return 2

    semgrep_findings = []
    if args.mode == "hybrid":
        semgrep = read_json(SEMGREP_PATH)
        if semgrep is None:
            console.print(f"[red]Hybrid mode needs {SEMGREP_PATH}; run reviewer.semgrep_run first.[/red]")
            return 2
        semgrep_findings = semgrep["findings"]

    import anthropic
    client = anthropic.Anthropic()
    tracker = CostTracker(args.model, load_prices(args.model))
    findings, errors, hints_given = [], [], 0
    for file, chunk in work:
        hints = None
        if args.mode == "hybrid":
            hints = hints_for_chunk(semgrep_findings, file, chunk["start"], chunk["end"])
            hints_given += len(hints)
        found, error = review_chunk(client, tracker, args.model, args.mode, file, chunk, hints)
        findings.extend(found)
        if error:
            errors.append({"file": file, "lines": [chunk["start"], chunk["end"]], "error": error})
        console.print(f"{file}:{chunk['start']}-{chunk['end']}  "
                      f"{len(found)} findings{'  [red]' + error + '[/red]' if error else ''}")

    findings = dedupe(findings)
    out_path = RESULTS_DIR / f"{args.mode}_findings.json"
    meta = {"tool": args.mode, "model": args.model, "files": args.files,
            "chunks": len(work), "chunk_errors": errors}
    if args.mode == "hybrid":
        meta["hints_given"] = hints_given
    write_json(out_path, {"meta": meta, "findings": findings})
    summary = tracker.summary()
    write_run(args.mode, summary)
    total = summary["total"]
    cost = "n/a (no prices.json entry)" if total["cost_usd"] is None else f"${total['cost_usd']:.4f}"
    console.print(f"{len(findings)} findings -> {out_path}\n{total['calls']} calls, "
                  f"{total['input_tokens']} in / {total['output_tokens']} out tokens, "
                  f"{total['latency_s']:.1f}s, cost {cost}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
