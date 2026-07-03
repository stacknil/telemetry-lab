# Operator Reproduction

This is the shortest local path for reproducing the reviewer contract from a
fresh clone. It does not add a new demo and does not require any live service,
cloud account, SIEM, dashboard, alert routing, case-management system, or
production telemetry source.

## Fresh Clone

```bash
git clone https://github.com/stacknil/telemetry-lab.git
cd telemetry-lab
python -m pip install -e ".[dev]"
```

Use the same Python interpreter for install, artifact regeneration, schema
validation, and tests.

## Reproduce v1.0 Artifacts

```bash
python scripts/regenerate_artifacts.py --check
```

Expected result:

- five demo jobs run from committed synthetic inputs
- `23` byte-stable committed artifacts match regenerated output
- `6` PNG visual snapshots regenerate as smoke checks without byte comparison

If this command fails, open an artifact regeneration issue with the command,
exit code, failing artifact path, and whether the failure is a missing file or
content difference.

## Full Reviewer Contract Gate

The v1.0 reviewer contract is the exact three-command gate:

```bash
python scripts/regenerate_artifacts.py --check
python -m pytest tests/test_evidence_pipeline_schemas.py
python -m pytest
```

For the same sequence with clearer step labels:

```bash
python scripts/check_release_contract.py
```

The wrapper stops at the first failed step and reports which gate failed.

## What This Does Not Prove

Passing the gate means the committed reviewer contract is locally reproducible.
It does not claim production readiness, operational detection quality, final
incident verdicts, live ingestion, or cloud-environment coverage.
