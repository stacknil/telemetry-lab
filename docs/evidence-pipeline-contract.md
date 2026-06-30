# Evidence Pipeline Contract

`telemetry-lab` v1.0 treats reviewer-facing JSON and JSONL artifacts as evidence pipeline contracts. The schemas below define the current machine-readable artifact shapes across the five-demo matrix without turning the repo into a SIEM, dashboard, or monitoring platform.

Use [`docs/vocabulary.md`](vocabulary.md) for the cross-demo meaning of `event`, `signal`, `hit`, `finding`, `case_bundle`, `summary`, `report`, and `audit_trace`.

The contract is intentionally local and file-based:

- schemas live under `schemas/`
- committed artifacts live under `demos/*/artifacts/`
- tests validate the schemas against the committed JSON artifacts and JSONL records
- raw evidence payloads may preserve source-specific fields, but deterministic wrapper fields stay explicit

## Schema Matrix

| Schema | Demo artifact | What it locks |
| --- | --- | --- |
| `schemas/telemetry_summary.schema.json` | `data/processed/summary.json`, `data/processed/richer_sample/summary.json` | telemetry-window run counts, rule counts, cooldown, and generated artifact references |
| `schemas/rule_hits.schema.json` | `demos/ai-assisted-detection-demo/artifacts/rule_hits.json` | deterministic rule-hit fields before case grouping |
| `schemas/case_bundles.schema.json` | `demos/ai-assisted-detection-demo/artifacts/case_bundles.json` | bounded case bundles passed to JSON-only drafting |
| `schemas/case_summaries.schema.json` | `demos/ai-assisted-detection-demo/artifacts/case_summaries.json` | accepted case summaries after schema and semantic validation |
| `schemas/ai_audit_traces.schema.json` | `demos/ai-assisted-detection-demo/artifacts/audit_traces.jsonl` | JSONL audit records for accepted and rejected AI-assisted drafting paths |
| `schemas/dedup_rule_hits.schema.json` | `demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_before_dedup.json`, `demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_after_dedup.json` | raw rule hits before deduplication and retained alert records after cooldown handling |
| `schemas/dedup_explanations.schema.json` | `demos/rule-evaluation-and-dedup-demo/artifacts/dedup_explanations.json` | retained/suppressed cooldown explanations |
| `schemas/config_change_events.schema.json` | `demos/config-change-investigation-demo/artifacts/change_events_normalized.json` | normalized risky-change input context before rule matching |
| `schemas/config_investigation_hits.schema.json` | `demos/config-change-investigation-demo/artifacts/investigation_hits.json` | full config-change investigation records with triggering changes and attached bounded evidence |
| `schemas/investigation_summary.schema.json` | `demos/config-change-investigation-demo/artifacts/investigation_summary.json` | config-change investigation summaries and bounded evidence counts |
| `schemas/cloudtrail_normalized_events.schema.json` | `demos/cloud-iam-change-investigation-demo/artifacts/normalized_cloudtrail_events.json` | normalized synthetic CloudTrail-like event records |
| `schemas/cloud_iam_findings.schema.json` | `demos/cloud-iam-change-investigation-demo/artifacts/investigation_signals.json` | bounded CloudTrail-like IAM findings |
| `schemas/cloud_iam_summary.schema.json` | `demos/cloud-iam-change-investigation-demo/artifacts/investigation_summary.json` | Cloud IAM investigation summary and time-model metadata |

## Contract Rules

- Schema files use JSON Schema Draft 2020-12.
- Contracted wrapper fields reject unknown properties unless the field intentionally preserves raw source evidence.
- Timestamps use RFC 3339 / JSON Schema `date-time` strings.
- Severity values are limited to `low`, `medium`, `high`, and `critical`.
- The Cloud IAM schemas preserve the event-time model: `eventTime` is normalized to `event_time`, optional `observedTime` is preserved as `observed_time`, and detection ordering is documented as `event_time`.
- These schemas describe reviewer evidence only. They do not claim production alert routing, case management, autonomous response, or final incident verdicts.

## Verification

Run:

```bash
python scripts/regenerate_artifacts.py --check
python -m pytest tests/test_evidence_pipeline_schemas.py
```

The regeneration check compares byte-stable CSV, JSON, JSONL, and Markdown artifacts with fresh pipeline output. It also regenerates PNG visual snapshots to verify that the plotting path still runs, but it does not byte-compare those images because Matplotlib rendering can vary across platforms.

The schema test validates each schema file and checks that every committed JSON artifact and JSONL record listed in the schema matrix conforms to it.

## Release Artifact Diff

Every release must include the artifact diff defined in
[`docs/reviewer-artifact-diff.md`](reviewer-artifact-diff.md). The diff must
cover added fields, removed fields, semantic changes, and compatibility notes
for changed reviewer artifacts, or state `no-artifact-change` when committed
reviewer artifacts are unchanged.
