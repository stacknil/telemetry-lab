# v1.1 Operator Reproduction Release Notes (Draft)

Theme: operator reproduction and issue triage, no demo expansion.

Release status: draft until a `v1.1` tag or GitHub release is explicitly
published.

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

Refresh this snapshot from the final release commit before publishing v1.1:

```bash
python scripts/check_release_contract.py
```

Expected gate sequence:

- artifact regeneration
- schema validation
- full test suite

## Boundaries

- No demo expansion.
- No live ingestion.
- No production SIEM or dashboard.
- No alert routing or case-management service.
- No autonomous response.
- No final incident verdict.

