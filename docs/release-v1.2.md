# v1.2 Architecture Cohesion Release Notes

Theme: architecture cohesion, no demo expansion.

Release status: implementation draft; not tagged until final clean-clone validation.

This release resolves the repository/package/version identity mismatch from v1.1 and keeps the five-demo reviewer contract stable.

## Release Scope

- Project metadata: `telemetry-lab==1.2.0`.
- Primary import package: `telemetry_lab`.
- Compatibility import package: `telemetry_window_demo`.
- Primary console script: `telemetry-lab`.
- Compatibility console script: `telemetry-window-demo`.

## Unified CLI

```bash
telemetry-lab run window --config configs/default.yaml
telemetry-lab run ai-assisted
telemetry-lab run dedup
telemetry-lab run config-change
telemetry-lab run cloud-iam
telemetry-lab verify
```

Legacy module commands remain available for older notes, but the reviewer-facing route uses `telemetry-lab`.

## Artifact Compatibility

Compatibility label: `additive-compatible`.

Added reviewer-facing artifact:

- `run_manifest.json` for each primary synthetic-local run.

Changed artifact reference:

- `data/processed/summary.json` and `data/processed/richer_sample/summary.json` now include `run_manifest.json` in `generated_artifacts`.

No existing v1.1 reviewer-facing artifact path is removed or renamed.

## Run Manifest

Each manifest records:

- `tool_version`
- `demo_id`
- `input_digest`
- `config_digest`
- `artifact_schema_versions`
- `execution_mode: synthetic-local`

Text-file input and config digests are canonicalized across LF and CRLF checkouts.

## Tests

- Adds property tests for window half-open boundary indexes.
- Adds property tests for dedup cooldown invariants.
- Keeps schema validation over every reviewer-facing JSON and JSONL artifact.

## Boundaries

- No demo expansion.
- No live ingestion.
- No production SIEM or dashboard.
- No alert routing or case-management service.
- No autonomous response.
- No final incident verdict.
- Notebooks are auxiliary exploration only; the core pipeline remains headless.
