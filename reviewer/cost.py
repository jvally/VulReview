"""Token, latency and cost tracking for every API call.

Prices come from prices.json (USD per million tokens, keyed by model ID). If the
file or the model entry is missing, cost fields are null and only tokens and
latency are reported.
"""
from __future__ import annotations

import time
from pathlib import Path

from .common import ROOT, RESULTS_DIR, read_json, write_json

PRICES_PATH = ROOT / "prices.json"
COST_LOG_PATH = RESULTS_DIR / "cost_log.json"


def load_prices(model: str, path: Path = PRICES_PATH) -> dict | None:
    entry = (read_json(path, default={}) or {}).get(model)
    if not isinstance(entry, dict):
        return None
    try:
        return {"input_per_mtok": float(entry["input_per_mtok"]),
                "output_per_mtok": float(entry["output_per_mtok"])}
    except (KeyError, TypeError, ValueError):
        return None


def estimate_cost(input_tokens: int, output_tokens: int, prices: dict | None) -> float | None:
    if prices is None:
        return None
    return (input_tokens * prices["input_per_mtok"] + output_tokens * prices["output_per_mtok"]) / 1_000_000


class CostTracker:
    def __init__(self, model: str, prices: dict | None = None):
        self.model = model
        self.prices = prices
        self.calls: list[dict] = []

    def record(self, file: str, input_tokens: int, output_tokens: int, latency_s: float) -> dict:
        call = {
            "file": file,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "latency_s": round(latency_s, 3),
            "cost_usd": estimate_cost(input_tokens, output_tokens, self.prices),
        }
        self.calls.append(call)
        return call

    def call(self, client, file: str, **kwargs):
        """Wrap client.messages.create, recording usage and wall-clock latency."""
        start = time.perf_counter()
        response = client.messages.create(**kwargs)
        latency = time.perf_counter() - start
        usage = response.usage
        # Cached tokens are billed at different rates; this tool does not use
        # caching, so they are folded into input for a conservative estimate.
        input_tokens = (usage.input_tokens
                        + (getattr(usage, "cache_creation_input_tokens", 0) or 0)
                        + (getattr(usage, "cache_read_input_tokens", 0) or 0))
        self.record(file, input_tokens, usage.output_tokens, latency)
        return response

    @staticmethod
    def _sum(calls: list[dict]) -> dict:
        costs = [c["cost_usd"] for c in calls]
        return {
            "calls": len(calls),
            "input_tokens": sum(c["input_tokens"] for c in calls),
            "output_tokens": sum(c["output_tokens"] for c in calls),
            "latency_s": round(sum(c["latency_s"] for c in calls), 3),
            "cost_usd": None if any(c is None for c in costs) else round(sum(costs), 6),
        }

    def summary(self) -> dict:
        per_file: dict[str, list[dict]] = {}
        for c in self.calls:
            per_file.setdefault(c["file"], []).append(c)
        return {
            "model": self.model,
            "prices": self.prices,
            "per_file": {f: self._sum(cs) for f, cs in per_file.items()},
            "total": self._sum(self.calls),
            "calls": self.calls,
        }


def write_run(run_name: str, data: dict, path: Path = COST_LOG_PATH) -> None:
    """Merge one run (llm / hybrid / semgrep) into cost_log.json."""
    log = read_json(path, default={}) or {}
    log.setdefault("runs", {})[run_name] = data
    write_json(path, log)
