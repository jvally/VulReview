import json

from reviewer.cost import CostTracker, estimate_cost, load_prices, write_run

PRICES = {"input_per_mtok": 2.0, "output_per_mtok": 10.0}


def test_estimate_cost():
    assert estimate_cost(1_000_000, 100_000, PRICES) == 3.0
    assert estimate_cost(1000, 1000, None) is None


def test_aggregation_per_file_and_run():
    t = CostTracker("m", PRICES)
    t.record("a.ts", 1000, 200, 1.5)
    t.record("a.ts", 500, 100, 0.5)
    t.record("b.ts", 2000, 300, 2.0)
    s = t.summary()
    assert s["per_file"]["a.ts"] == {"calls": 2, "input_tokens": 1500, "output_tokens": 300,
                                     "latency_s": 2.0, "cost_usd": 0.006}
    assert s["total"]["calls"] == 3 and s["total"]["input_tokens"] == 3500
    assert s["total"]["cost_usd"] == 0.013


def test_without_prices_reports_tokens_and_latency_only():
    t = CostTracker("m", None)
    t.record("a.ts", 1000, 200, 1.5)
    total = t.summary()["total"]
    assert total["cost_usd"] is None and total["input_tokens"] == 1000 and total["latency_s"] == 1.5


def test_load_prices(tmp_path):
    path = tmp_path / "prices.json"
    assert load_prices("m", path) is None  # file missing
    path.write_text(json.dumps({"m": PRICES, "bad": {"input_per_mtok": "x"}}))
    assert load_prices("m", path) == PRICES
    assert load_prices("other", path) is None and load_prices("bad", path) is None


def test_write_run_merges_runs(tmp_path):
    path = tmp_path / "cost_log.json"
    write_run("llm", {"total": 1}, path)
    write_run("hybrid", {"total": 2}, path)
    assert json.loads(path.read_text())["runs"] == {"llm": {"total": 1}, "hybrid": {"total": 2}}
