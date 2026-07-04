# v1.1 Operator Reproduction Release Notes

Theme: operator reproduction and issue triage, no demo expansion.

Release status: published as tag `v1.1`.

## Scope

v1.1 keeps the existing five-demo matrix unchanged:

1. `telemetry-window-demo`
2. `ai-assisted-detection-demo`
3. `rule-evaluation-and-dedup-demo`
4. `config-change-investigation-demo`
5. `cloud-iam-change-investigation-demo`

This release is about helping an outside operator reproduce the frozen v1.0
reviewer contract from a clean local checkout. It does not add a sixth demo, a
live data source, a dashboard, alert routing, case management, autonomous
response, or final incident verdicts.

## Operator Reproduction

The maintained operator path is [`docs/operator-reproduction.md`](operator-reproduction.md):

1. install the repo with the dev extra
2. run all five demos locally
3. regenerate committed artifacts with `python scripts/regenerate_artifacts.py --check`
4. validate schemas with `python -m pytest tests/test_evidence_pipeline_schemas.py`
5. run the full test suite with `python -m pytest`

For a labeled one-command wrapper, run:

```bash
python scripts/check_release_contract.py
```

## Issue Triage

v1.1 adds focused issue templates for operator-facing contract questions:

- schema drift reports
- artifact regeneration failures
- demo boundary questions
- documentation reproduction questions

These templates keep reports scoped to local, synthetic reviewer artifacts and
ask reporters not to include credentials, real account IDs, production telemetry,
or private data.

## Validation Snapshot

The final release candidate was verified from clean Windows and Linux clones:

| Environment | Python | Artifact gate | Schema tests | Full tests |
| --- | --- | --- | --- | --- |
| Windows | 3.14.3 | 23 committed artifacts matched; 6 visual snapshots regenerated as smoke checks | 3 passed | 182 passed |
| Linux (Ubuntu) | 3.12.3 | 23 committed artifacts matched; 6 visual snapshots regenerated as smoke checks | 3 passed | 182 passed |

The normalized SHA-256 manifests for all 30 tracked artifact paths were
identical across the two clones. Text artifacts were normalized from CRLF to
LF before hashing; binary artifacts were hashed byte-for-byte.

## Artifact Diff

`no-artifact-change`: v1.1 does not change committed reviewer-facing artifact
content, field meaning, schemas, or filenames. It adds operator reproduction,
release-gate, and issue-triage surfaces around the frozen v1.0 artifact
contract.

## v1.2 Blocker

Package identity mismatch must be resolved before v1.2: the repository and
release identity is `telemetry-lab` / `v1.1`, while `pyproject.toml` still
declares `telemetry-window-demo==0.1.0`. Resolve the project name and version as
one coordinated metadata change before a v1.2 tag or any package publication.
No package registry publication is part of v1.1.

## Boundaries

- No demo expansion.
- No live ingestion.
- No production SIEM or dashboard.
- No alert routing or case-management service.
- No autonomous response.
- No final incident verdict.

