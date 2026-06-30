# v1.0 Reviewer Contract Release Notes

**This is a reviewer-contract release, not a production SIEM.**

Release status: v1.0 reviewer-contract release. Publication is gated by
[`docs/v1-readiness-gate.md`](v1-readiness-gate.md).

## Release Scope

v1.0 freezes the current five-demo reviewer contract:

1. `telemetry-window-demo`
2. `ai-assisted-detection-demo`
3. `rule-evaluation-and-dedup-demo`
4. `config-change-investigation-demo`
5. `cloud-iam-change-investigation-demo`

Demo expansion is closed. The release consolidates the current local,
file-based workflows instead of adding another demo or production platform
surface.

## Reviewer Contract

The v1.0 release contract requires:

- fixed synthetic inputs for the five demos
- fixed reviewer-visible output paths
- JSON Schema validation for reviewer-facing JSON and JSONL evidence artifacts
- reproducible committed artifacts
- a passing full test suite

See [`docs/v1-contract-freeze.md`](v1-contract-freeze.md) for the freeze scope
and [`docs/evidence-pipeline-contract.md`](evidence-pipeline-contract.md) for the
schema matrix.

## Artifact Compatibility

Relative to `v0.6.0`:

- the fourth-demo artifact paths and committed contents remain unchanged
- the fifth demo adds four reviewer-visible artifact paths under its own demo
  directory
- the overall artifact compatibility label is `additive-compatible`
- the two demo-local `investigation_summary.json` files use separate schemas
  and intentionally different root shapes

See [`docs/v0.6-to-v1-artifact-diff.md`](v0.6-to-v1-artifact-diff.md) for the
field-level and semantic diff. Future release diffs follow
[`docs/reviewer-artifact-diff.md`](reviewer-artifact-diff.md).

## Validation Snapshot

Validation snapshot from the release candidate commit:

```bash
python scripts/regenerate_artifacts.py --check
python -m pytest tests/test_evidence_pipeline_schemas.py
python -m pytest
```

- Artifact regeneration: passed; `23` committed artifacts matched and `6`
  visual snapshots completed smoke checks.
- Schema validation: passed; `3 passed`.
- Full test suite: passed; `175 passed`.

If any required command fails, v1.0 is not ready.

## Boundaries

- Synthetic, local, file-based inputs only.
- No live AWS account or production telemetry source.
- No real account ID or credentials.
- No production detection claim or operational alerting claim.
- No real-time ingestion, dashboard, alert routing, or case-management service.
- No autonomous response.
- No final incident verdict.

This release does not claim production readiness.
