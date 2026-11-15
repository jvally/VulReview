from eval.evaluate import compare, cwe_family, matches, score

TRUTH = [
    {"id": "T1", "file": "a.ts", "line_start": 34, "line_end": 34, "cwe": "CWE-89"},
    {"id": "T2", "file": "b.ts", "line_start": 18, "line_end": 20, "cwe": "CWE-943"},
]


def f(file, start, end, cwe):
    return {"file": file, "line_start": start, "line_end": end, "cwe": cwe, "severity": "high"}


def test_line_tolerance_boundaries():
    assert matches(f("a.ts", 39, 39, "CWE-89"), TRUTH[0])
    assert matches(f("a.ts", 29, 29, "CWE-89"), TRUTH[0])
    assert not matches(f("a.ts", 40, 41, "CWE-89"), TRUTH[0])
    assert matches(f("a.ts", 10, 60, "CWE-89"), TRUTH[0])  # enclosing range


def test_file_and_family_must_match():
    assert not matches(f("b.ts", 34, 34, "CWE-89"), TRUTH[0])
    assert not matches(f("a.ts", 34, 34, "CWE-79"), TRUTH[0])
    assert matches(f("b.ts", 18, 18, "CWE-89"), TRUTH[1])  # SQL and NoSQL share a family


def test_families():
    assert cwe_family("CWE-95") == cwe_family("CWE-94") == "injection-code"
    assert cwe_family("CWE-862") == cwe_family("CWE-639")
    assert cwe_family("CWE-79") == "CWE-79"
    assert cwe_family("CWE-0") != cwe_family("CWE-89")


def test_score_precision_recall_and_duplicates():
    findings = [f("a.ts", 34, 34, "CWE-89"), f("a.ts", 33, 35, "CWE-564"), f("a.ts", 70, 70, "CWE-79")]
    s = score(findings, TRUTH)
    assert s["true_positive_findings"] == 2 and len(s["false_positives"]) == 1
    assert s["truth_found"] == ["T1"] and s["truth_missed"] == ["T2"]
    assert s["precision"] == 0.667 and s["recall"] == 0.5


def test_score_no_findings():
    s = score([], TRUTH)
    assert s["precision"] is None and s["recall"] == 0.0


def test_compare_unique_and_missed():
    scores = {"semgrep": {"truth_found": ["T1"]}, "llm": {"truth_found": ["T1", "T2"]}}
    c = compare(scores)
    assert c["llm"]["only_this"] == ["T2"]
    assert c["semgrep"]["only_this"] == []
    assert c["semgrep"]["missed_but_found_by"] == {"llm": ["T2"]}
