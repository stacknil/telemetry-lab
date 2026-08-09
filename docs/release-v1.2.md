# v1.2 Architecture Cohesion Release Notes

Theme: architecture cohesion, no demo expansion.

Release status: published as tag `v1.2`.

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

Changed manifest metadata:

- `config_digest` now derives from the shipped YAML content during artifact regeneration without reserializing the config, matching the public CLI manifest identity while retaining LF/CRLF canonicalization.

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

## Validation Snapshot

The release candidate was verified from a fresh GitHub clone on Windows with
Python 3.14.3:

| Environment | Artifact gate | Schema tests | Full tests | Consumer reproduction |
| --- | --- | --- | --- | --- |
| Clean clone | 29 committed artifacts matched; 6 visual snapshots regenerated as smoke checks | 4 passed | 190 passed | `telemetry-lab run window`, legacy `telemetry_window_demo.cli`, and `telemetry-lab verify` passed |

The package installed as `telemetry-lab==1.2.0`; both the `telemetry-lab` and
`telemetry-window-demo` console entrypoints were available. Visual snapshots
are smoke-checked by the release gate and are not required to be byte-identical
across plotting environments.

## Boundaries

- No demo expansion.
- No live ingestion.
- No production SIEM or dashboard.
- No alert routing or case-management service.
- No autonomous response.
- No final incident verdict.
- Notebooks are auxiliary exploration only; the core pipeline remains headless.
