# Config-Change Investigation Demo

This demo is part of `telemetry-lab` and stays intentionally small, local, and reviewer-friendly.

It focuses on deterministic investigation logic for risky configuration changes and nearby evidence. There is no new AI stage in this demo.

## Purpose

The goal is to make one compact config-change investigation path legible from committed sample data.

The demo starts from configuration changes, policy denials, and follow-on telemetry, then:

- normalizes the inputs into shared internal records
- applies deterministic risky-change rules
- attaches nearby supporting evidence using bounded time and shared-system correlation
- writes machine-readable summaries and a short reviewer-facing report

## Quick Start

From the repository root:

```bash
python -m pip install -e .
python -m telemetry_window_demo.cli run-config-change-demo
```

Generated artifacts are written to `demos/config-change-investigation-demo/artifacts/`.

For offline review without running the demo, see [`docs/config-change-investigation-reviewer-pack.md`](../../docs/config-change-investigation-reviewer-pack.md).

## Demo Inputs

- config changes: `data/raw/config_changes.jsonl`
- policy denials: `data/raw/policy_denials.jsonl`
- follow-on events: `data/raw/follow_on_events.jsonl`
- investigation config: `config/investigation.yaml`

The bundled sample includes:

- one risky MFA-related change with nearby denials and follow-on signals
- one risky public-bind change with nearby denials and service events
- one benign config change that should not trigger an investigation
- one risky break-glass change with no nearby supporting evidence inside the bounded window

## Deterministic Correlation

This demo uses a bounded correlation window after each triggering config change.

Evidence is attached only when:

1. `target_system` matches the triggering change
2. the evidence timestamp falls within the configured correlation window after the change

## Expected Artifacts

- `artifacts/change_events_normalized.json`
- `artifacts/investigation_hits.json`
- `artifacts/investigation_summary.json`
- `artifacts/investigation_report.md`

## Artifact Semantics

- `change_events_normalized.json`: normalized config changes before any rule match is applied
- `investigation_hits.json`: full investigation records, including the triggering change and attached evidence
- `investigation_summary.json`: reduced machine-readable summaries for each investigation
- `investigation_report.md`: a short reviewer report showing the trigger, evidence counts, and bounded-correlation explanation

## Reviewer Walkthrough

1. Open `change_events_normalized.json` and identify the risky config keys and values.
2. Open `investigation_hits.json` and verify which changes became investigations and which evidence records were attached.
3. Open `investigation_summary.json` and confirm the final summaries stay deterministic and bounded.
4. Open `investigation_report.md` and verify that a risky change with no nearby evidence remains explicit rather than silently discarded.

## Limitations

- synthetic sample data only
- no realtime ingestion or service deployment
- bounded correlation by system and time only
- no model-generated reasoning or autonomous response
