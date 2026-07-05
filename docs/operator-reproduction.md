# Operator Reproduction

This is the shortest local path for reproducing the reviewer contract from a
fresh clone. It does not add a new demo and does not require any live service,
cloud account, SIEM, dashboard, alert routing, case-management system, or
production telemetry source.

## Install

```bash
git clone https://github.com/stacknil/telemetry-lab.git
cd telemetry-lab
python -m pip install -e ".[dev]"
```

Use the same Python interpreter for install, demo runs, artifact regeneration,
schema validation, and tests.

## Run The Five Demos

```bash
telemetry-lab run window --config configs/default.yaml
telemetry-lab run ai-assisted
telemetry-lab run dedup
telemetry-lab run config-change
telemetry-lab run cloud-iam
```

Expected operator checkpoints:

- `data/processed/summary.json` reports `41` events, `24` windows, and `12`
  alerts for `telemetry-window-demo`.
- Every run writes `run_manifest.json` with `execution_mode: synthetic-local`.
- `demos/ai-assisted-detection-demo/artifacts/case_report.md` reports `3`
  deterministic cases.
- `demos/rule-evaluation-and-dedup-demo/artifacts/dedup_report.md` reports
  `10` raw hits reduced to `6` retained alerts.
- `demos/config-change-investigation-demo/artifacts/investigation_report.md`
  reports `4` normalized changes and `3` investigations.
- `demos/cloud-iam-change-investigation-demo/artifacts/investigation_report.md`
  reports `14` CloudTrail-like events and `5` investigation signals.

## Regenerate Artifacts

```bash
python scripts/regenerate_artifacts.py --check
```

Expected result:

- five demo jobs run from committed synthetic inputs
- `29` byte-stable committed artifacts match regenerated output
- `6` PNG visual snapshots regenerate as smoke checks without byte comparison

If this command fails, open an artifact regeneration issue with the command,
exit code, failing artifact path, and whether the failure is a missing file or
content difference.

## Schema Tests

```bash
python -m pytest tests/test_evidence_pipeline_schemas.py
```

This validates reviewer-facing JSON and JSONL artifacts against the schemas in
`schemas/`.

## Full Tests

```bash
python -m pytest
```

## Release Contract Gate

The reviewer contract is the exact three-command gate:

```bash
python scripts/regenerate_artifacts.py --check
python -m pytest tests/test_evidence_pipeline_schemas.py
python -m pytest
```

For the same sequence with clearer step labels:

```bash
telemetry-lab verify
```

The wrapper stops at the first failed step and reports which gate failed.

The script form remains available:

```bash
python scripts/check_release_contract.py
```

## What This Does Not Prove

Passing the gate means the committed reviewer contract is locally reproducible.
It does not claim production readiness, operational detection quality, final
incident verdicts, live ingestion, or cloud-environment coverage.
