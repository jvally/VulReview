import pytest

from reviewer.llm_review import chunk_lines, dedupe


def test_short_file_is_one_chunk():
    chunks = chunk_lines([f"l{i}" for i in range(1, 41)])
    assert len(chunks) == 1
    assert (chunks[0]["start"], chunks[0]["end"]) == (1, 40)


def test_chunks_overlap_and_cover_every_line():
    lines = [f"l{i}" for i in range(1, 401)]
    chunks = chunk_lines(lines, size=150, overlap=20)
    assert [(c["start"], c["end"]) for c in chunks] == [(1, 150), (131, 280), (261, 400)]
    covered = set()
    for c in chunks:
        assert c["lines"] == lines[c["start"] - 1:c["end"]]
        covered.update(range(c["start"], c["end"] + 1))
    assert covered == set(range(1, 401))


def test_exact_multiple_has_no_empty_tail():
    assert len(chunk_lines(["x"] * 150, size=150, overlap=20)) == 1


def test_empty_file_and_bad_params():
    assert chunk_lines([]) == []
    with pytest.raises(ValueError):
        chunk_lines(["x"], size=10, overlap=10)


def test_dedupe_drops_overlap_repeats_only():
    a = {"file": "f", "cwe": "CWE-89", "line_start": 140, "line_end": 142}
    b = {"file": "f", "cwe": "CWE-89", "line_start": 141, "line_end": 141}
    c = {"file": "f", "cwe": "CWE-79", "line_start": 141, "line_end": 141}
    assert dedupe([a, b, c]) == [a, c]
