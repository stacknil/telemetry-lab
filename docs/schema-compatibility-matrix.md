# Schema Compatibility Matrix

This matrix records reviewer-facing JSON and JSONL schema contracts for the v1.2 Architecture Cohesion Release. It is a local reviewer contract, not a production SIEM schema registry.

## Compatibility Labels

- `unchanged-v1`: schema and artifact shape are unchanged from v1.1.
- `additive-compatible`: v1.2 adds a reviewer artifact or reference without removing existing fields.
- `semantic-change`: field meaning changed and downstream consumers should inspect behavior.
- `breaking-artifact-change`: artifact path or required field removal.

## Matrix

| Schema | Version label | Artifact paths | v1.1 to v1.2 compatibility |
| --- | --- | --- | --- |
| `schemas/run_manifest.schema.json` | `run-manifest/v1` | `data/processed/run_manifest.json`; `data/processed/richer_sample/run_manifest.json`; each `demos/*/artifacts/run_manifest.json` | `additive-compatible`: new per-run provenance artifact |
| `schemas/telemetry_summary.schema.json` | `telemetry-summary/v1` | `data/processed/summary.json`; `data/processed/richer_sample/summary.json` | `additive-compatible`: `generated_artifacts` now includes `run_manifest.json` |
| `schemas/rule_hits.schema.json` | `rule-hits/v1` | `demos/ai-assisted-detection-demo/artifacts/rule_hits.json` | `unchanged-v1` |
| `schemas/case_bundles.schema.json` | `case-bundles/v1` | `demos/ai-assisted-detection-demo/artifacts/case_bundles.json` | `unchanged-v1` |
| `schemas/case_summaries.schema.json` | `ai-assisted-case-summary/v1` | `demos/ai-assisted-detection-demo/artifacts/case_summaries.json` | `unchanged-v1` |
| `schemas/ai_audit_traces.schema.json` | `ai-assisted-detection-audit/v1` | `demos/ai-assisted-detection-demo/artifacts/audit_traces.jsonl` | `unchanged-v1` |
| `schemas/dedup_rule_hits.schema.json` | `dedup-rule-hits/v1` | `demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_before_dedup.json`; `demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_after_dedup.json` | `unchanged-v1` |
| `schemas/dedup_explanations.schema.json` | `dedup-explanations/v1` | `demos/rule-evaluation-and-dedup-demo/artifacts/dedup_explanations.json` | `unchanged-v1` |
| `schemas/config_change_events.schema.json` | `config-change-events/v1` | `demos/config-change-investigation-demo/artifacts/change_events_normalized.json` | `unchanged-v1` |
| `schemas/config_investigation_hits.schema.json` | `config-investigation-hits/v1` | `demos/config-change-investigation-demo/artifacts/investigation_hits.json` | `unchanged-v1` |
| `schemas/investigation_summary.schema.json` | `investigation-summary/v1` | `demos/config-change-investigation-demo/artifacts/investigation_summary.json` | `unchanged-v1` |
| `schemas/cloudtrail_normalized_events.schema.json` | `cloudtrail-normalized-events/v1` | `demos/cloud-iam-change-investigation-demo/artifacts/normalized_cloudtrail_events.json` | `unchanged-v1` |
| `schemas/cloud_iam_findings.schema.json` | `cloud-iam-findings/v1` | `demos/cloud-iam-change-investigation-demo/artifacts/investigation_signals.json` | `unchanged-v1` |
| `schemas/cloud_iam_summary.schema.json` | `cloud-iam-summary/v1` | `demos/cloud-iam-change-investigation-demo/artifacts/investigation_summary.json` | `unchanged-v1` |

## Run Manifest Contract

Every primary run writes a manifest with `execution_mode` set to `synthetic-local`:

```json
{
  "tool_version": "1.2.0",
  "demo_id": "window",
  "input_digest": "sha256:...",
  "config_digest": "sha256:...",
  "input_file_digests": {
    "data/raw/sample_events.jsonl": "sha256:..."
  },
  "config_file_digests": {
    "configs/default.yaml": "sha256:..."
  },
  "artifact_schema_versions": {
    "run_manifest": "run-manifest/v1",
    "telemetry_summary": "telemetry-summary/v1"
  },
  "execution_mode": "synthetic-local"
}
```

The aggregate `input_digest` and `config_digest` fields retain the v1.2
contract: labels are sorted before hashing and UTF-8 text inputs are
canonicalized across LF and CRLF checkouts. The per-file `*_file_digests` maps
are a separate provenance contract: each value hashes the exact shipped bytes
(`read_bytes()`, including line endings), each key is a normalized
repository-relative POSIX path, and keys are emitted in lexical order. YAML is
not parsed and reserialized for either per-file digest. These fingerprints are
not signatures and do not imply live telemetry coverage.

The per-file maps are emitted by current writers but remain optional in the
schema so older v1 manifests remain readable. Consumers that need file-level
provenance should require and validate the maps explicitly.

## Boundaries

- No live account or production telemetry source is required.
- No schema in this matrix represents alert routing, case management, autonomous response, or final incident verdicts.
- Notebooks may explore committed data, but the compatibility contract is the headless CLI plus committed artifacts and tests.
