import json

import pytest

from reviewer.common import clean_finding, normalise_cwe, validate_finding
from reviewer.llm_review import parse_findings

GOOD = {"file": "routes/login.ts", "line_start": 34, "line_end": 34, "cwe": "CWE-89",
        "severity": "high", "explanation": "SQL built from input", "suggested_fix": "Use bound parameters"}
CHUNK = {"start": 1, "end": 83, "lines": []}


def test_valid_finding():
    assert validate_finding(GOOD) == []


@pytest.mark.parametrize("patch", [
    {"line_start": 0}, {"line_start": "34"}, {"line_start": 40}, {"cwe": "SQLi"},
    {"severity": "severe"}, {"explanation": ""}, {"line_end": True},
])
def test_invalid_values(patch):
    assert validate_finding({**GOOD, **patch})


def test_missing_field_and_non_object():
    assert validate_finding({k: v for k, v in GOOD.items() if k != "suggested_fix"})
    assert validate_finding("nope")


def test_source_required_only_in_hybrid():
    assert validate_finding(GOOD, require_source=True)
    assert validate_finding({**GOOD, "source": "guess"}, require_source=True)
    assert validate_finding({**GOOD, "source": "llm_only"}, require_source=True) == []


def test_line_range_check():
    assert validate_finding(GOOD, line_range=(1, 30))
    assert validate_finding(GOOD, line_range=(1, 83)) == []


def test_cwe_normalisation():
    assert normalise_cwe("cwe-89: SQL Injection") == "CWE-89"
    assert normalise_cwe(918) == "CWE-918"
    assert normalise_cwe("injection") is None
    assert clean_finding({**GOOD, "cwe": "cwe_089", "severity": "HIGH"})["cwe"] == "CWE-89"


def test_parse_accepts_fenced_json_and_forces_file():
    text = "```json\n" + json.dumps({"findings": [{**GOOD, "file": "wrong.ts"}]}) + "\n```"
    out = parse_findings(text, "routes/login.ts", CHUNK, "llm")
    assert out[0]["file"] == "routes/login.ts"


@pytest.mark.parametrize("text", ["Here you go: {}", "[]", '{"findings": [{"file": "x"}]}'])
def test_parse_rejects_malformed(text):
    with pytest.raises(ValueError):
        parse_findings(text, "routes/login.ts", CHUNK, "llm")
