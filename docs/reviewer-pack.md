# Reviewer Pack

This is the top-level reviewer pack for `telemetry-lab`.

Use it as a short, no-guessing path through the repository. The project is a local, file-based detection workflow lab: it is not a SIEM, not a dashboard, and not a production monitoring platform.

## What to Review

Start with the stable demo matrix in [`docs/reviewer-path.md`](reviewer-path.md). It maps common review questions to the demo and artifacts that answer them:

| Review question | Demo | Primary evidence |
| --- | --- | --- |
| How are raw events converted to alert features? | `telemetry-window-demo` | `data/processed/features.csv`, `data/processed/alerts.csv`, `data/processed/summary.json` |
| How is AI constrained? | `ai-assisted-detection-demo` | `demos/ai-assisted-detection-demo/artifacts/case_summaries.json`, `demos/ai-assisted-detection-demo/artifacts/audit_traces.jsonl`, guardrails in `demos/ai-assisted-detection-demo/README.md` |
| How are duplicate alerts reduced? | `rule-evaluation-and-dedup-demo` | `demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_before_dedup.json`, `demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_after_dedup.json`, `demos/rule-evaluation-and-dedup-demo/artifacts/dedup_explanations.json` |
| How are risky config changes investigated? | `config-change-investigation-demo` | `demos/config-change-investigation-demo/artifacts/investigation_hits.json`, `demos/config-change-investigation-demo/artifacts/investigation_report.md` |

## Architecture

See [`docs/architecture.md`](architecture.md) for the repository-level workflow diagram.

The important shape is:

1. committed sample inputs and configs
2. deterministic local pipelines
3. bounded AI drafting only where explicitly marked
4. committed or regenerated artifacts
5. reviewer inspection through docs, tests, and reports

## Artifact Naming Contract

The current artifact names are reviewer-facing contracts for the v0.7 / v1.0 consolidation path.

- Keep the demo matrix stable unless a demo is intentionally retired.
- Prefer additive artifacts over renaming existing reviewer-visible outputs.
- If an artifact must be renamed, update the README, reviewer path, this reviewer pack, demo README, tests, and committed sample outputs in the same change.
- Do not introduce platform-style names that imply alert routing, case management, real-time ingestion, or autonomous response.

### Stable Reviewer-Visible Artifacts

| Area | Stable artifact paths |
| --- | --- |
| Default telemetry sample | `data/processed/features.csv`, `data/processed/alerts.csv`, `data/processed/summary.json`, `data/processed/event_count_timeline.png`, `data/processed/error_rate_timeline.png`, `data/processed/alerts_timeline.png` |
| Richer telemetry sample | `data/processed/richer_sample/features.csv`, `data/processed/richer_sample/alerts.csv`, `data/processed/richer_sample/summary.json`, `data/processed/richer_sample/event_count_timeline.png`, `data/processed/richer_sample/error_rate_timeline.png`, `data/processed/richer_sample/alerts_timeline.png` |
| AI-assisted detection demo | `demos/ai-assisted-detection-demo/artifacts/rule_hits.json`, `demos/ai-assisted-detection-demo/artifacts/case_bundles.json`, `demos/ai-assisted-detection-demo/artifacts/case_summaries.json`, `demos/ai-assisted-detection-demo/artifacts/case_report.md`, `demos/ai-assisted-detection-demo/artifacts/audit_traces.jsonl` |
| Rule dedup demo | `demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_before_dedup.json`, `demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_after_dedup.json`, `demos/rule-evaluation-and-dedup-demo/artifacts/dedup_explanations.json`, `demos/rule-evaluation-and-dedup-demo/artifacts/dedup_report.md` |
| Config-change investigation demo | `demos/config-change-investigation-demo/artifacts/change_events_normalized.json`, `demos/config-change-investigation-demo/artifacts/investigation_hits.json`, `demos/config-change-investigation-demo/artifacts/investigation_summary.json`, `demos/config-change-investigation-demo/artifacts/investigation_report.md` |

## Fast Verification

From the repository root:

```bash
python -m pip install -e ".[dev]"
python -m telemetry_window_demo.cli run --config configs/default.yaml
python -m telemetry_window_demo.cli run-ai-demo
python -m telemetry_window_demo.cli run-rule-dedup-demo
python -m telemetry_window_demo.cli run-config-change-demo
pytest
```

Use the same Python interpreter for install, tests, and demo commands.

## Review Anchors

- [`docs/reviewer-brief.md`](reviewer-brief.md): short problem / value summary
- [`docs/reviewer-path.md`](reviewer-path.md): demo choice by review question
- [`docs/architecture.md`](architecture.md): local file-based workflow diagram
- [`docs/sample-output.md`](sample-output.md): committed output counts and sample artifacts
- [`tests/test_reviewer_docs.py`](../tests/test_reviewer_docs.py): regression checks for reviewer-facing docs

## Boundaries

- No production monitoring claims
- No real-time ingestion or streaming state
- No dashboard, alert routing, or case-management service
- No autonomous response actions
- No final incident verdicts from the AI-assisted demo
