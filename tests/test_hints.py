from reviewer.llm_review import build_system, build_user_prompt, hints_for_chunk, review_chunk
from reviewer.cost import CostTracker

SEMGREP = [
    {"file": "a.ts", "line_start": 34, "line_end": 34, "cwe": "CWE-89", "rule_id": "r.sqli", "explanation": "tainted SQL"},
    {"file": "a.ts", "line_start": 200, "line_end": 201, "cwe": "CWE-95", "rule_id": "r.eval", "explanation": "eval"},
    {"file": "b.ts", "line_start": 34, "line_end": 34, "cwe": "CWE-22", "rule_id": "r.path", "explanation": "path"},
]
CHUNK = {"start": 1, "end": 3, "lines": ["one", "two", "three"]}


def test_hints_selected_by_file_and_range():
    assert [h["rule_id"] for h in hints_for_chunk(SEMGREP, "a.ts", 1, 150)] == ["r.sqli"]
    assert [h["rule_id"] for h in hints_for_chunk(SEMGREP, "a.ts", 131, 280)] == ["r.eval"]
    assert hints_for_chunk(SEMGREP, "c.ts", 1, 150) == []


def test_boundary_hint_included_in_both_overlapping_chunks():
    hint = [{**SEMGREP[0], "line_start": 140, "line_end": 140}]
    assert hints_for_chunk(hint, "a.ts", 1, 150) and hints_for_chunk(hint, "a.ts", 131, 280)


def test_llm_prompt_has_numbered_code_and_no_hints():
    prompt = build_user_prompt("a.ts", CHUNK)
    assert "1: one" in prompt and "3: three" in prompt
    assert "Static analysis hints" not in prompt
    assert "semgrep_confirmed" not in build_system("llm")


def test_hybrid_prompt_injects_hints_with_caveat():
    prompt = build_user_prompt("a.ts", CHUNK, [SEMGREP[0]])
    assert "may be wrong or incomplete" in prompt
    assert "lines 34-34, CWE-89, rule r.sqli: tainted SQL" in prompt
    assert "semgrep_confirmed|llm_only" in build_system("hybrid")


def test_hybrid_prompt_with_no_hints_says_so():
    assert "reported nothing" in build_user_prompt("a.ts", CHUNK, [])


class _Block:
    type = "text"

    def __init__(self, text):
        self.text = text


class _Usage:
    input_tokens, output_tokens = 100, 20


class _Response:
    stop_reason, usage = "end_turn", _Usage()

    def __init__(self, text):
        self.content = [_Block(text)]


class _FakeClient:
    """Stands in for anthropic.Anthropic(); returns queued replies."""

    def __init__(self, replies):
        self.replies, self.requests = list(replies), []
        self.messages = self

    def create(self, **kwargs):
        self.requests.append(kwargs)
        return _Response(self.replies.pop(0))


GOOD = ('{"findings": [{"file": "a.ts", "line_start": 2, "line_end": 2, "cwe": "CWE-89", "severity": "high", '
        '"explanation": "x", "suggested_fix": "y"}]}')


def test_retries_once_on_malformed_json_then_succeeds():
    client, tracker = _FakeClient(["not json", GOOD]), CostTracker("m")
    findings, error = review_chunk(client, tracker, "m", "llm", "a.ts", CHUNK, None)
    assert error is None and len(findings) == 1
    assert len(client.requests) == 2 and "rejected" in client.requests[1]["messages"][0]["content"]
    assert len(tracker.calls) == 2  # the retry is costed too


def test_gives_up_after_one_retry():
    client = _FakeClient(["nope", "still nope"])
    findings, error = review_chunk(client, CostTracker("m"), "m", "llm", "a.ts", CHUNK, None)
    assert findings == [] and "malformed" in error and len(client.requests) == 2
