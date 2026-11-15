"""Shared paths, scope, schema validation and small IO helpers."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET_DIR = ROOT / "target"
RESULTS_DIR = ROOT / "results"

# Files in scope: the intentionally vulnerable Juice Shop clone only.
SCOPE_FILES = [
    "routes/login.ts",
    "routes/search.ts",
    "routes/updateProductReviews.ts",
    "routes/trackOrder.ts",
    "routes/showProductReviews.ts",
    "routes/b2bOrder.ts",
    "routes/userProfile.ts",
    "routes/profileImageUrlUpload.ts",
    "routes/fileUpload.ts",
    "routes/basket.ts",
]

SEVERITIES = ("low", "medium", "high", "critical")
SOURCES = ("semgrep_confirmed", "llm_only")
REQUIRED_FIELDS = ("file", "line_start", "line_end", "cwe", "severity", "explanation", "suggested_fix")
_CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)


def normalise_cwe(value) -> str | None:
    """'cwe-89', 'CWE-89: SQL Injection', 89 -> 'CWE-89'. None if unparseable."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"CWE-{value}"
    if isinstance(value, str):
        m = _CWE_RE.search(value)
        if m:
            return f"CWE-{int(m.group(1))}"
        if value.strip().isdigit():
            return f"CWE-{int(value.strip())}"
    return None


def validate_finding(finding, *, require_source: bool = False,
                     line_range: tuple[int, int] | None = None) -> list[str]:
    """Return a list of schema errors (empty list means valid)."""
    if not isinstance(finding, dict):
        return ["finding is not an object"]
    errors = []
    for field in REQUIRED_FIELDS:
        if field not in finding:
            errors.append(f"missing field '{field}'")
    if errors:
        return errors
    for field in ("file", "explanation", "suggested_fix"):
        if not isinstance(finding[field], str) or not finding[field].strip():
            errors.append(f"'{field}' must be a non-empty string")
    for field in ("line_start", "line_end"):
        v = finding[field]
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            errors.append(f"'{field}' must be a positive integer")
    if not errors and finding["line_start"] > finding["line_end"]:
        errors.append("'line_start' must be <= 'line_end'")
    if not errors and line_range is not None:
        lo, hi = line_range
        if finding["line_start"] < lo or finding["line_end"] > hi:
            errors.append(f"lines {finding['line_start']}-{finding['line_end']} outside reviewed range {lo}-{hi}")
    if normalise_cwe(finding["cwe"]) is None:
        errors.append("'cwe' must look like 'CWE-<number>'")
    if not isinstance(finding["severity"], str) or finding["severity"].lower() not in SEVERITIES:
        errors.append(f"'severity' must be one of {SEVERITIES}")
    if require_source and finding.get("source") not in SOURCES:
        errors.append(f"'source' must be one of {SOURCES}")
    return errors


def clean_finding(finding: dict) -> dict:
    """Normalise a validated finding (canonical CWE, lower-case severity)."""
    out = dict(finding)
    out["cwe"] = normalise_cwe(finding["cwe"])
    out["severity"] = finding["severity"].lower()
    return out


def load_dotenv(path: Path = ROOT / ".env") -> None:
    """Minimal .env loader; never overrides variables already set."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        if value:
            os.environ.setdefault(key.strip(), value)


def read_json(path: Path, default=None):
    if not Path(path).exists():
        return default
    return json.loads(Path(path).read_text())


def write_json(path: Path, data) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2) + "\n")
