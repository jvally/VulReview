# LLM security code reviewer vs Semgrep

A small CLI that reviews source files for vulnerabilities with the Anthropic API and benchmarks three
configurations against hand-verified ground truth on [OWASP Juice Shop](https://github.com/juice-shop/juice-shop),
an intentionally vulnerable app:

| Configuration | What runs |
|---|---|
| `semgrep` | `semgrep --config auto` only |
| `llm` | The model reviews each file chunk with no other input |
| `hybrid` | The model reviews each chunk and is given Semgrep's hits for that chunk as hints it may confirm, reject or extend |

Defensive use only. The tool refuses files outside `./target`, and the prompt asks for remediation, not exploits.

## How to run

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
git clone --depth 1 https://github.com/juice-shop/juice-shop.git target
cp .env.example .env            # set ANTHROPIC_API_KEY and REVIEW_MODEL
cp prices.example.json prices.json   # optional: fill in $/MTok for your model

python -m pytest                              # unit tests, no API calls
python -m reviewer.semgrep_run                # -> results/semgrep_findings.json
python -m reviewer.llm_review --mode llm --dry-run    # shows the call count, sends nothing
python -m reviewer.llm_review --mode llm      # -> results/llm_findings.json
python -m reviewer.llm_review --mode hybrid   # -> results/hybrid_findings.json (needs the Semgrep file)
python -m eval.evaluate                       # -> results/results.md, results/results.json
```

There is no default model: pass `--model <id>` or set `REVIEW_MODEL`. Without `prices.json`, cost columns
show `n/a` and only tokens and latency are reported (`results/cost_log.json`).

## How it works

- **Scope**: ten files under `target/routes/` (listed in `reviewer/common.py`).
- **Chunking**: 150 lines with 20 lines of overlap; code is sent with line numbers so findings use real lines.
- **Output**: JSON only, validated against a schema (`file, line_start, line_end, cwe, severity, explanation,
  suggested_fix`, plus `source` in hybrid mode). Malformed output is retried once, then recorded as a chunk error.
- **Cost**: every API call goes through `reviewer/cost.py`, which records input tokens, output tokens, latency and
  estimated cost per file and per run.
- **Evaluation**: a finding matches a truth entry when it is in the same file, within ±5 lines, and in the same
  CWE family (for example CWE-89 and CWE-943 are both query injection). Precision is matched findings over all
  findings; recall is distinct truth entries found over ten.

## Ground truth

`eval/truth.json` holds ten Juice Shop vulnerabilities, each tied to a challenge key in
`data/static/challenges.yml` and verified by reading the code at the cloned commit. One entry (T10) is flagged
because its CWE label is a judgement call. Five candidates were left out as uncertain and are listed in the same
file with the reason.

RESULTS_PLACEHOLDER
