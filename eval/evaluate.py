"""Score Semgrep, LLM and hybrid findings against eval/truth.json.

A finding matches a truth entry when it is in the same file, its line range
comes within LINE_TOLERANCE lines of the truth range, and the CWEs are in the
same family.
"""
from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from reviewer.common import RESULTS_DIR, normalise_cwe, read_json, write_json

TRUTH_PATH = Path(__file__).resolve().parent / "truth.json"
LINE_TOLERANCE = 5
CONFIGS = ("semgrep", "llm", "hybrid")

CWE_FAMILIES = {
    "injection-query": {89, 564, 943},
    "injection-code": {94, 95, 1336},
    "path-traversal": {22, 23, 73, 98},
    "ssrf": {918},
    "access-control": {284, 285, 639, 862, 863},
}


def cwe_family(cwe) -> str:
    norm = normalise_cwe(cwe)
    if norm is None:
        return "unknown"
    number = int(norm.split("-")[1])
    for family, members in CWE_FAMILIES.items():
        if number in members:
            return family
    return norm


def matches(finding: dict, truth: dict, tolerance: int = LINE_TOLERANCE) -> bool:
    return (finding["file"] == truth["file"]
            and finding["line_start"] <= truth["line_end"] + tolerance
            and finding["line_end"] >= truth["line_start"] - tolerance
            and cwe_family(finding["cwe"]) == cwe_family(truth["cwe"]))


def score(findings: list[dict], truth: list[dict]) -> dict:
    """Precision counts every finding that matches a truth entry as correct (a second
    finding on the same entry is a duplicate, not a false positive). Recall counts
    distinct truth entries found."""
    true_pos, false_pos, found_ids = [], [], set()
    for f in findings:
        hit = next((t for t in truth if matches(f, t)), None)
        if hit:
            true_pos.append({**f, "truth_id": hit["id"]})
            found_ids.add(hit["id"])
        else:
            false_pos.append(f)
    return {
        "findings": len(findings),
        "true_positive_findings": len(true_pos),
        "truth_found": sorted(found_ids),
        "truth_missed": sorted(t["id"] for t in truth if t["id"] not in found_ids),
        "precision": round(len(true_pos) / len(findings), 3) if findings else None,
        "recall": round(len(found_ids) / len(truth), 3) if truth else None,
        "true_positives": true_pos,
        "false_positives": false_pos,
    }


def compare(scores: dict[str, dict]) -> dict:
    """Per configuration: truth entries only it found, and entries it missed that another found."""
    out = {}
    for name, s in scores.items():
        others = {o: set(scores[o]["truth_found"]) for o in scores if o != name}
        mine = set(s["truth_found"])
        union_others = set().union(*others.values()) if others else set()
        out[name] = {
            "only_this": sorted(mine - union_others),
            "missed_but_found_by": {o: sorted(found - mine) for o, found in others.items()},
        }
    return out


def cost_columns(name: str, s: dict, cost_log: dict) -> dict:
    run = (cost_log.get("runs") or {}).get(name)
    if run is None:
        return {"total_cost_usd": None, "cost_per_true_positive_usd": None, "seconds_per_file": None}
    if name == "semgrep":
        return {"total_cost_usd": None, "cost_per_true_positive_usd": None,
                "seconds_per_file": run["seconds_per_file"]}
    total = run["total"]
    n_files, n_tp = max(len(run["per_file"]), 1), len(s["truth_found"])
    cost = total["cost_usd"]
    return {
        "total_cost_usd": cost,
        "cost_per_true_positive_usd": round(cost / n_tp, 6) if cost is not None and n_tp else None,
        "seconds_per_file": round(total["latency_s"] / n_files, 3),
        "input_tokens": total["input_tokens"],
        "output_tokens": total["output_tokens"],
        "model": run["model"],
    }


def _fmt(value, pattern="{}"):
    return "n/a" if value is None else pattern.format(value)


def render_markdown(results: dict, truth: list[dict]) -> str:
    lines = ["# Results", "",
             f"Ground truth: {len(truth)} entries. Match rule: same file, lines within ±{LINE_TOLERANCE}, same CWE family.", "",
             "| Configuration | Findings | TP findings | Truth found | Precision | Recall | Total cost | Cost / TP | Seconds / file |",
             "|---|---|---|---|---|---|---|---|---|"]
    for name, r in results["configurations"].items():
        c = r["cost"]
        lines.append(f"| {name} | {r['findings']} | {r['true_positive_findings']} | "
                     f"{len(r['truth_found'])}/{len(truth)} | {_fmt(r['precision'], '{:.2f}')} | "
                     f"{_fmt(r['recall'], '{:.2f}')} | {_fmt(c['total_cost_usd'], '${:.4f}')} | "
                     f"{_fmt(c['cost_per_true_positive_usd'], '${:.4f}')} | {_fmt(c['seconds_per_file'], '{:.2f}')} |")
    if results["not_run"]:
        lines += ["", "Not run (no findings file): " + ", ".join(results["not_run"]) + "."]
    lines += ["", "## Truth coverage", "", "| ID | File | Lines | CWE | " + " | ".join(results["configurations"]) + " |",
              "|---|---|---|---|" + "---|" * len(results["configurations"])]
    for t in truth:
        marks = " | ".join("yes" if t["id"] in r["truth_found"] else "no" for r in results["configurations"].values())
        lines.append(f"| {t['id']} | {t['file']} | {t['line_start']}-{t['line_end']} | {t['cwe']} | {marks} |")
    for name, r in results["configurations"].items():
        cmp_ = results["comparison"][name]
        lines += ["", f"## {name}", "",
                  f"- Found only by this configuration: {', '.join(cmp_['only_this']) or 'none'}"]
        for other, ids in cmp_["missed_but_found_by"].items():
            lines.append(f"- Missed here but found by {other}: {', '.join(ids) or 'none'}")
        lines += ["", "True positives:"]
        lines += [f"- {f['truth_id']}: {f['file']}:{f['line_start']}-{f['line_end']} {f['cwe']}" for f in r["true_positives"]] or ["- none"]
        lines += ["", "False positives (unmatched findings; some are real issues outside the 10 truth entries):"]
        lines += [f"- {f['file']}:{f['line_start']}-{f['line_end']} {f['cwe']} ({f['severity']})" for f in r["false_positives"]] or ["- none"]
    return "\n".join(lines) + "\n"


def evaluate(results_dir: Path = RESULTS_DIR, truth_path: Path = TRUTH_PATH) -> dict:
    truth = read_json(truth_path)["entries"]
    cost_log = read_json(results_dir / "cost_log.json", default={}) or {}
    scores, not_run = {}, []
    for name in CONFIGS:
        data = read_json(results_dir / f"{name}_findings.json")
        if data is None:
            not_run.append(name)
            continue
        scores[name] = score(data["findings"], truth)
        scores[name]["cost"] = cost_columns(name, scores[name], cost_log)
    return {"line_tolerance": LINE_TOLERANCE, "truth_entries": len(truth), "not_run": not_run,
            "configurations": scores, "comparison": compare(scores)}


def main() -> int:
    results = evaluate()
    truth = read_json(TRUTH_PATH)["entries"]
    write_json(RESULTS_DIR / "results.json", results)
    (RESULTS_DIR / "results.md").write_text(render_markdown(results, truth))
    table = Table(title="Benchmark vs ground truth")
    for col in ("Config", "Findings", "Truth found", "Precision", "Recall", "Cost", "Cost/TP", "s/file"):
        table.add_column(col)
    for name, r in results["configurations"].items():
        c = r["cost"]
        table.add_row(name, str(r["findings"]), f"{len(r['truth_found'])}/{len(truth)}",
                      _fmt(r["precision"], "{:.2f}"), _fmt(r["recall"], "{:.2f}"),
                      _fmt(c["total_cost_usd"], "${:.4f}"), _fmt(c["cost_per_true_positive_usd"], "${:.4f}"),
                      _fmt(c["seconds_per_file"], "{:.2f}"))
    console = Console()
    console.print(table)
    if results["not_run"]:
        console.print(f"Not run: {', '.join(results['not_run'])}")
    console.print(f"Wrote {RESULTS_DIR / 'results.md'} and results.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
