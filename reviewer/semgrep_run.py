"""Run Semgrep on the in-scope files and normalise results to the shared schema."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from rich.console import Console

from .common import RESULTS_DIR, SCOPE_FILES, TARGET_DIR, normalise_cwe, write_json
from .cost import write_run

OUT_PATH = RESULTS_DIR / "semgrep_findings.json"
_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low",
             "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def normalise(result: dict) -> dict:
    """Convert one Semgrep JSON result to the shared finding schema."""
    extra = result.get("extra", {})
    cwes = extra.get("metadata", {}).get("cwe") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    cwe = next((c for c in (normalise_cwe(x) for x in cwes) if c), None)
    rule_id = result.get("check_id", "unknown-rule")
    return {
        "file": result["path"],
        "line_start": result["start"]["line"],
        "line_end": result["end"]["line"],
        "cwe": cwe or "CWE-0",  # CWE-0 = rule carries no CWE metadata
        "severity": _SEVERITY.get(str(extra.get("severity", "")).upper(), "medium"),
        "explanation": (extra.get("message") or rule_id).strip(),
        "suggested_fix": extra.get("fix") or f"No autofix provided; see Semgrep rule {rule_id}.",
        "rule_id": rule_id,
    }


def run_semgrep(files: list[str], target_dir: Path = TARGET_DIR) -> tuple[dict, float]:
    cmd = ["semgrep", "--config", "auto", "--json", "--quiet", *files]
    start = time.perf_counter()
    proc = subprocess.run(cmd, cwd=target_dir, capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    if proc.returncode not in (0, 1):  # 1 = findings present
        raise RuntimeError(f"semgrep failed ({proc.returncode}): {proc.stderr[-2000:]}")
    return json.loads(proc.stdout), elapsed


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", nargs="*", default=SCOPE_FILES,
                        help="paths relative to ./target (default: built-in scope)")
    args = parser.parse_args(argv)
    console = Console()
    missing = [f for f in args.files if not (TARGET_DIR / f).is_file()]
    if missing:
        console.print(f"[red]Not found under {TARGET_DIR}: {missing}[/red]")
        return 2
    raw, elapsed = run_semgrep(args.files)
    findings = [normalise(r) for r in raw.get("results", [])]
    findings.sort(key=lambda f: (f["file"], f["line_start"]))
    write_json(OUT_PATH, {
        "meta": {"tool": "semgrep", "config": "auto", "version": raw.get("version"),
                 "files": args.files, "errors": len(raw.get("errors", []))},
        "findings": findings,
    })
    write_run("semgrep", {"seconds_total": round(elapsed, 3), "files": len(args.files),
                          "seconds_per_file": round(elapsed / len(args.files), 3)})
    console.print(f"Semgrep: {len(findings)} findings in {elapsed:.1f}s -> {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
