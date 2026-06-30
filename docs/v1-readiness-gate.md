# v1.0 Readiness Gate

`telemetry-lab` is ready for v1.0 only when the current five-demo matrix is frozen, reproducible, schema-validated, and test-clean.

This gate is a release-readiness checklist, not a feature roadmap. It does not authorize new demos, live ingestion, dashboards, alert routing, case management, autonomous response, or final incident verdicts.

## Five-Demo Matrix

The fixed v1.0 matrix is:

1. `telemetry-window-demo`
2. `ai-assisted-detection-demo`
3. `rule-evaluation-and-dedup-demo`
4. `config-change-investigation-demo`
5. `cloud-iam-change-investigation-demo`

## Required Conditions

v1.0 requires all of the following:

1. Fixed inputs
2. Fixed outputs
3. Schema validation
4. Artifact regeneration
5. Test pass

If any condition fails, v1.0 is not ready.

## Fixed Inputs

The committed sample inputs for the five demos are part of the reviewer contract.

Before v1.0:

- keep the existing five-demo matrix fixed
- keep raw sample input paths stable unless a rename is intentionally documented across README, reviewer docs, demo docs, tests, and committed artifacts
- keep sample inputs synthetic, local, privacy-preserving, and reviewer-verifiable
- do not add a sixth demo or live data source for v1.0

## Fixed Outputs

Reviewer-visible outputs are part of the contract.

Before v1.0:

- keep stable artifact paths listed in [`docs/reviewer-pack.md`](reviewer-pack.md#stable-reviewer-visible-artifacts)
- keep output semantics aligned with [`docs/evidence-pipeline-contract.md`](evidence-pipeline-contract.md)
- verify the `v0.6.0` fourth-demo compatibility baseline in [`docs/v0.6-to-v1-artifact-diff.md`](v0.6-to-v1-artifact-diff.md)
- document any intentional artifact shape change in [`docs/reviewer-artifact-diff.md`](reviewer-artifact-diff.md)
- use `no-artifact-change` when committed reviewer artifacts are unchanged for a release

## Schema Validation

Reviewer-facing JSON and JSONL evidence artifacts must validate against schemas under `schemas/`.

Before v1.0:

```bash
python -m pytest tests/test_evidence_pipeline_schemas.py
```

This verifies that schema files are valid JSON Schema Draft 2020-12 documents and that committed JSON artifacts and JSONL records conform to the schema matrix.

## Artifact Regeneration

Committed artifacts must match fresh local pipeline output.

Before v1.0:

```bash
python scripts/regenerate_artifacts.py --check
```

This is the artifact drift gate. It byte-compares stable CSV, JSON, JSONL, and Markdown artifacts and smoke-checks generated PNG timelines without byte comparison.

## Test Pass

The full local test suite must pass.

Before v1.0:

```bash
python -m pytest
```

The suite covers CLI behavior, demo pipelines, schema validation, reviewer docs, markdown links, event-time semantics, bounded correlation language, and artifact regeneration.

## Release Decision

Treat the release as ready only when this exact sequence passes from the repository root:

```bash
python scripts/regenerate_artifacts.py --check
python -m pytest tests/test_evidence_pipeline_schemas.py
python -m pytest
```

The v1.0 release notes in [`docs/release-v1.0.md`](release-v1.0.md) should include the command results, should state whether the reviewer-facing artifact diff is `no-artifact-change` or documents intentional compatibility changes, and must retain the exact boundary statement: "This is a reviewer-contract release, not a production SIEM."
