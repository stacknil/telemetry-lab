# Reviewer Path

`telemetry-lab` is a controlled detection workflow portfolio. It is not a SIEM, not a dashboard, and not an unfinished monitoring platform.

The repo is intentionally local and file-based so reviewers can verify each workflow from committed sample inputs to generated artifacts without live infrastructure, alert routing, or autonomous response behavior.

## Choose a demo by review question

| Question | Demo | What to inspect |
| --- | --- | --- |
| How are raw events converted to alert features? | `telemetry-window-demo` | `data/processed/features.csv`, `data/processed/alerts.csv`, `data/processed/summary.json` |
| How is AI constrained? | `ai-assisted-detection-demo` | `demos/ai-assisted-detection-demo/artifacts/case_summaries.json`, `demos/ai-assisted-detection-demo/artifacts/audit_traces.jsonl`, guardrails in `demos/ai-assisted-detection-demo/README.md` |
| How are duplicate alerts reduced? | `rule-evaluation-and-dedup-demo` | `demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_before_dedup.json`, `demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_after_dedup.json`, `demos/rule-evaluation-and-dedup-demo/artifacts/dedup_explanations.json` |
| How are risky config changes investigated? | `config-change-investigation-demo` | `demos/config-change-investigation-demo/artifacts/investigation_hits.json`, `demos/config-change-investigation-demo/artifacts/investigation_report.md` |
| How are IAM changes investigated from CloudTrail-like events? | `cloud-iam-change-investigation-demo` | `demos/cloud-iam-change-investigation-demo/artifacts/investigation_signals.json`, `demos/cloud-iam-change-investigation-demo/artifacts/investigation_report.md` |

## Fast verification commands

From the repository root:

Use the same Python interpreter for install, tests, and demo commands. On machines with multiple Python installs, replace `python` with the intended interpreter path.

```bash
python -m pip install -e ".[dev]"
python -m telemetry_window_demo.cli run --config configs/default.yaml
python -m telemetry_window_demo.cli run-ai-demo
python -m telemetry_window_demo.cli run-rule-dedup-demo
python -m telemetry_window_demo.cli run-config-change-demo
python -m telemetry_window_demo.cli run-cloud-iam-change-demo
pytest
```

## Expected boundaries

- No production monitoring claims
- No real-time ingestion or streaming state
- No alert routing, dashboard, or case-management service
- No autonomous response actions
- No final incident verdicts from the AI-assisted demo

The reviewer value is the workflow evidence: deterministic inputs, visible intermediate artifacts, constrained summaries, and reports that make detection behavior inspectable.
