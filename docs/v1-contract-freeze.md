# v1.0 Five-Demo Contract Freeze

`telemetry-lab` v1.0 freezes the reviewer contract around the current five-demo
matrix. This milestone is not about adding another demo or expanding the
project into a SIEM, dashboard, or monitoring platform. It is about making the
current local, file-based detection workflow lab reviewer-verifiable from a
stable contract surface.

## Release Status

The latest tagged release is `v1.0`, published as a reviewer-contract release
for the five-demo matrix. It includes the synthetic CloudTrail-like IAM
investigation demo, the v1 reviewer contract stabilization docs, schema
coverage for reviewer-facing JSON and JSONL artifacts, and the artifact
regeneration gate.

`v0.6.0` remains the fourth-demo compatibility baseline. It was published as
`v0.6.0 - fourth demo and config-change investigation`.

Use [`docs/v0.6-to-v1-artifact-diff.md`](v0.6-to-v1-artifact-diff.md) for the
concrete artifact and compatibility change from the fourth demo in `v0.6.0` to
the fifth demo in the v1 release.

## Freeze Scope

The v1.0 freeze scope is the existing five-demo matrix:

1. `telemetry-window-demo`
2. `ai-assisted-detection-demo`
3. `rule-evaluation-and-dedup-demo`
4. `config-change-investigation-demo`
5. `cloud-iam-change-investigation-demo`

No new demo should be added for v1.0. Any v1.0 work should improve contract
clarity, artifact reproducibility, release notes, schema coverage, or reviewer
navigation for this matrix.

## Freeze Gate

Use [`docs/v1-readiness-gate.md`](v1-readiness-gate.md) as the release-readiness gate for fixed inputs, fixed outputs, schema validation, artifact regeneration, and test pass requirements.

Before a v1.0 release candidate, run the following from the repository root:

```bash
python scripts/regenerate_artifacts.py --check
python -m pytest
```

The first command is the v1.0 artifact drift gate. It regenerates the committed
demo outputs and checks that byte-stable reviewer-facing artifacts still match
the pipeline output. PNG timeline snapshots are regenerated as smoke checks
without byte comparison because Matplotlib rendering can vary across platforms.

The test suite then checks CLI behavior, schemas, reviewer docs, link integrity,
time semantics, bounded correlation language, and release artifact diff
requirements.

## Contract Checklist

For v1.0, keep these surfaces frozen or intentionally updated together:

- five-demo matrix in the README, reviewer path, reviewer pack, roadmap, and
  tests
- reviewer-visible artifact names in
  [`docs/reviewer-pack.md`](reviewer-pack.md#stable-reviewer-visible-artifacts)
- JSON schema contracts in
  [`docs/evidence-pipeline-contract.md`](evidence-pipeline-contract.md)
- cross-demo vocabulary in [`docs/vocabulary.md`](vocabulary.md)
- bounded correlation boundaries in [`docs/vocabulary.md`](vocabulary.md#bounded-correlation)
- release artifact diff requirements in
  [`docs/reviewer-artifact-diff.md`](reviewer-artifact-diff.md)
- committed artifact regeneration through
  `python scripts/regenerate_artifacts.py --check`

If any of these surfaces changes, update the corresponding docs, tests, and
committed sample outputs in the same change.

## Release Notes Requirement

Use [`docs/release-v1.0.md`](release-v1.0.md) as the maintained v1.0 release
notes. The release notes must state exactly:

> This is a reviewer-contract release, not a production SIEM.

The v1.0 release notes should also include:

- a `no new demo` statement
- the five-demo matrix
- the artifact regeneration check result
- the full test command and result
- the reviewer-facing artifact diff required by
  [`docs/reviewer-artifact-diff.md`](reviewer-artifact-diff.md)
- compatibility notes for any changed artifact shape or semantics since
  `v0.6.0`

Do not publish v1.0 as a feature expansion. Publish it as a five-demo contract
freeze.
