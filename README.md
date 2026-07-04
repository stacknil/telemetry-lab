# telemetry-lab

[![CI](https://github.com/stacknil/telemetry-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/stacknil/telemetry-lab/actions/workflows/ci.yml)

A local, file-based detection workflow lab for reviewer-verifiable telemetry and detection demos.

Current focus: v1 reviewer contract stabilization for the five-demo matrix. v1.1 is an Operator Reproduction Release, not another demo expansion.

Latest tagged release: [v1.1 — operator reproduction release](https://github.com/stacknil/telemetry-lab/releases/tag/v1.1).

## Reviewer Start

- [`docs/reviewer-brief.md`](docs/reviewer-brief.md): scope, value, evidence, and boundaries
- [`docs/reviewer-path.md`](docs/reviewer-path.md): choose the right demo by review question
- [`docs/reviewer-pack.md`](docs/reviewer-pack.md): demo matrix, artifact contract, and v1 readiness gate
- [`docs/operator-reproduction.md`](docs/operator-reproduction.md): shortest local path from clone to verifying all five demos
- [`docs/release-v1.1.md`](docs/release-v1.1.md): v1.1 operator reproduction and issue triage release notes
- [`docs/v1-contract-freeze.md`](docs/v1-contract-freeze.md): v1.0 five-demo contract freeze, release status, and contract scope
- [`docs/v1-readiness-gate.md`](docs/v1-readiness-gate.md): fixed inputs, fixed outputs, schema validation, artifact regeneration, and test pass requirements
- [`docs/release-v1.0.md`](docs/release-v1.0.md): v1.0 reviewer-contract release notes and explicit non-SIEM boundary
- [`docs/v0.6-to-v1-artifact-diff.md`](docs/v0.6-to-v1-artifact-diff.md): fourth-to-fifth-demo artifact contract and compatibility diff
- [`docs/evidence-pipeline-contract.md`](docs/evidence-pipeline-contract.md): JSON/JSONL schema contracts for reviewer-facing evidence artifacts
- [`docs/reviewer-artifact-diff.md`](docs/reviewer-artifact-diff.md): release artifact diff contract for reviewer-facing outputs
- [`docs/vocabulary.md`](docs/vocabulary.md): cross-demo vocabulary for events, hits, signals, bounded correlation, findings, summaries, reports, and audit traces
- [`docs/README.md`](docs/README.md): current route, supporting docs, and historical release evidence

## Demos

- [telemetry-window-demo](#telemetry-window-demo)
- [ai-assisted-detection-demo](demos/ai-assisted-detection-demo/README.md)
- [rule-evaluation-and-dedup-demo](demos/rule-evaluation-and-dedup-demo/README.md)
- [config-change-investigation-demo](demos/config-change-investigation-demo/README.md)
- [cloud-iam-change-investigation-demo](demos/cloud-iam-change-investigation-demo/README.md)

| Demo | Input | Deterministic core | LLM role | Main artifacts | Guardrails / non-goals |
| --- | --- | --- | --- | --- | --- |
| [telemetry-window-demo](#telemetry-window-demo) | JSONL / CSV events | Windows<br>Features<br>Alert thresholds | None | `features.csv`<br>`alerts.csv`<br>`summary.json`<br>3 PNG plots | Local demo only<br>No realtime<br>No case management |
| [ai-assisted-detection-demo](demos/ai-assisted-detection-demo/README.md) | JSONL auth / web / process | Normalize<br>Rules<br>Grouping<br>ATT&CK mapping | JSON-only case drafting | `rule_hits.json`<br>`case_bundles.json`<br>`case_summaries.json`<br>`case_report.md`<br>`audit_traces.jsonl` | Human verification required<br>No autonomous response<br>No final verdict |
| [rule-evaluation-and-dedup-demo](demos/rule-evaluation-and-dedup-demo/README.md) | JSON raw rule hits | Scope resolution<br>Cooldown grouping<br>Suppression reasoning | None | `rule_hits_before_dedup.json`<br>`rule_hits_after_dedup.json`<br>`dedup_explanations.json`<br>`dedup_report.md` | No realtime<br>No dashboard<br>No AI stage |
| [config-change-investigation-demo](demos/config-change-investigation-demo/README.md) | JSONL config changes<br>Policy denials<br>Follow-on events | Normalize<br>Risky-change rules<br>Bounded correlation | None | `change_events_normalized.json`<br>`investigation_hits.json`<br>`investigation_summary.json`<br>`investigation_report.md` | No realtime<br>No dashboard<br>No AI stage |
| [cloud-iam-change-investigation-demo](demos/cloud-iam-change-investigation-demo/README.md) | Synthetic CloudTrail-like JSONL | Validate<br>IAM rules<br>Bounded correlation<br>ATT&CK mapping | None | `normalized_cloudtrail_events.json`<br>`investigation_signals.json`<br>`investigation_summary.json`<br>`investigation_report.md` | Synthetic only<br>No live AWS<br>No final verdict |

## What This Repo Is

`telemetry-lab` is a small portfolio repository for constrained detection workflows. It is not a SIEM, dashboard, or monitoring platform; it is organized as five local, file-based demos that are reproducible from committed sample data and intentionally scoped for public review rather than production use.

### telemetry-window-demo

`telemetry-window-demo` turns timestamped event streams into sliding-window feature tables, cooldown-reduced rule-based alerts, PNG timeline plots, and machine-readable run summaries.

### ai-assisted-detection-demo

`ai-assisted-detection-demo` uses deterministic normalization, detection, case grouping, and ATT&CK mapping, then limits the LLM to JSON-only case summarization. Human verification is required, there is no autonomous response, and the demo does not produce a final incident verdict.

### rule-evaluation-and-dedup-demo

`rule-evaluation-and-dedup-demo` starts from raw rule hits and makes cooldown behavior legible. It shows which hits were kept, which were suppressed, how scope was resolved, and why repeated hits collapsed into fewer retained alerts.

### config-change-investigation-demo

`config-change-investigation-demo` follows risky configuration changes into bounded follow-on evidence such as policy denials and service signals. It stays deterministic, file-based, and review-oriented, with no added AI stage.

### cloud-iam-change-investigation-demo

`cloud-iam-change-investigation-demo` uses synthetic CloudTrail-like events to review IAM changes, failed console logins, CloudTrail logging changes, and security group ingress changes with bounded deterministic rules. It has no live AWS account, no real account ID, no production detection claim, and no final incident verdict.

## Quick Run

```bash
python -m pip install -e .
python -m telemetry_window_demo.cli run --config configs/default.yaml
```

Use the same Python interpreter for install, tests, and demo commands. On machines with multiple Python installs, replace `python` with the intended interpreter path.
To run the test suite in a fresh environment, install the dev extra with `python -m pip install -e ".[dev]"`.

## Verify Locally In 3 Commands

If you want to verify v1.0 locally, run these three commands.

```bash
python scripts/regenerate_artifacts.py --check
python -m pytest tests/test_evidence_pipeline_schemas.py
python -m pytest
```

For the same reviewer-friendly gate with labeled steps, run:

```bash
python scripts/check_release_contract.py
```

Other demo entrypoints:

- `python -m telemetry_window_demo.cli run-ai-demo`
- `python -m telemetry_window_demo.cli run-rule-dedup-demo`
- `python -m telemetry_window_demo.cli run-config-change-demo`
- `python -m telemetry_window_demo.cli run-cloud-iam-change-demo`
- `python scripts/regenerate_artifacts.py --check`

Useful inspection commands:

- `python -m telemetry_window_demo.cli summarize --input data/raw/sample_events.jsonl`

For CSV inputs, pass a `.csv` file to `--input`; use `--timestamp-col` when the timestamp column is not named `timestamp`.

The `run --config configs/default.yaml` command reads `data/raw/sample_events.jsonl` and regenerates:

- `data/processed/features.csv`
- `data/processed/alerts.csv`
- `data/processed/summary.json`
- `data/processed/event_count_timeline.png`
- `data/processed/error_rate_timeline.png`
- `data/processed/alerts_timeline.png`

With the bundled default sample, the current repo state produces:

- `41` normalized events
- `24` windows
- `12` alerts after a `60` second cooldown

Why it is worth a quick look:

- it shows a full telemetry path from raw events to operator-facing outputs
- the sample inputs and outputs are reproducible in-repo
- a second bundled scenario gives a slightly richer walkthrough without changing the basic CLI flow

![Default alert timeline](data/processed/alerts_timeline.png)

## Reviewer Path

For a quick coherence pass across the demos:

1. Run `python -m telemetry_window_demo.cli run --config configs/default.yaml` and confirm `data/processed/summary.json` reports `41` events, `24` windows, and `12` alerts.
2. Run `python -m telemetry_window_demo.cli run-rule-dedup-demo` and confirm `demos/rule-evaluation-and-dedup-demo/artifacts/dedup_report.md` shows `10` raw hits reduced to `6` retained alerts with `4` suppressions.
3. Run `python -m telemetry_window_demo.cli run-config-change-demo` and confirm `demos/config-change-investigation-demo/artifacts/investigation_report.md` shows `4` normalized changes, `3` risky changes, and `3` investigations.
4. Run `python -m telemetry_window_demo.cli run-cloud-iam-change-demo` and confirm `demos/cloud-iam-change-investigation-demo/artifacts/investigation_report.md` shows `14` CloudTrail-like events and `5` investigation signals.
5. Run `python -m telemetry_window_demo.cli run-ai-demo` and confirm `demos/ai-assisted-detection-demo/artifacts/case_report.md` shows `3` deterministic cases with human verification and no final incident verdict.

## Demo Variants

Default sample:

- config: [`configs/default.yaml`](configs/default.yaml)
- input: `data/raw/sample_events.jsonl`
- outputs: `data/processed/`
- current summary: `41` events, `24` windows, `12` alerts, `summary.json` included

Richer sample:

- config: [`configs/richer_sample.yaml`](configs/richer_sample.yaml)
- input: `data/raw/richer_sample_events.jsonl`
- outputs: `data/processed/richer_sample/`
- current summary: `28` events, `24` windows, `8` alerts, `summary.json` included

## Input Support

Runtime input support:

- `.jsonl`
- `.csv`

Required fields for both formats on every row or record:

- `timestamp` by default, or the column named by `time.timestamp_col` in a run config
- `event_type`
- `source`
- `target`
- `status`

Input and output validation:

- run configs reject unknown top-level, time, feature, and rule fields to catch typos
- config paths, event inputs, and plot CSV inputs must point to files
- required event fields must be present and non-empty
- custom timestamp columns cannot reuse required event field names
- plot input tables validate required columns, datetime values, numeric ranges, and window bounds

Cooldown behavior:

- repeated alerts are keyed by `(rule_name, scope)`
- scope prefers the first available entity-like field in this order: `entity`, `source`, `target`, `host`
- when no entity-like field is present, cooldown falls back to per-`rule_name` behavior

## Repo Guide

- [`demos/rule-evaluation-and-dedup-demo/README.md`](demos/rule-evaluation-and-dedup-demo/README.md) explains the third demo and links its committed before/after dedup artifacts
- [`demos/config-change-investigation-demo/README.md`](demos/config-change-investigation-demo/README.md) explains the config-change investigation demo and its committed artifacts
- [`demos/cloud-iam-change-investigation-demo/README.md`](demos/cloud-iam-change-investigation-demo/README.md) explains the synthetic CloudTrail-like IAM investigation demo and its committed artifacts
- [`docs/README.md`](docs/README.md) indexes current reviewer docs, supporting design notes, and historical release evidence
- [`docs/operator-reproduction.md`](docs/operator-reproduction.md) gives the shortest local path from clone to running the five demos, artifact regeneration, schema tests, and full tests
- [`docs/release-v1.1.md`](docs/release-v1.1.md) records the v1.1 operator reproduction and issue triage release
- [`docs/reviewer-pack.md`](docs/reviewer-pack.md) is the top-level no-guessing reviewer pack and artifact naming contract
- [`docs/v1-contract-freeze.md`](docs/v1-contract-freeze.md) defines the v1.0 five-demo contract freeze gate
- [`docs/v1-readiness-gate.md`](docs/v1-readiness-gate.md) defines the fixed-input, fixed-output, schema-validation, artifact-regeneration, and test-pass readiness gate
- [`docs/v0.6-to-v1-artifact-diff.md`](docs/v0.6-to-v1-artifact-diff.md) explains the additive artifact contract from the fourth demo to the fifth
- [`docs/evidence-pipeline-contract.md`](docs/evidence-pipeline-contract.md) maps v1 evidence schemas to committed JSON artifacts
- [`docs/reviewer-artifact-diff.md`](docs/reviewer-artifact-diff.md) defines the release diff format for reviewer-facing artifact changes
- [`docs/reviewer-brief.md`](docs/reviewer-brief.md) gives the short problem, value, evidence, and boundary summary
- [`docs/reviewer-path.md`](docs/reviewer-path.md) maps common review questions to the right demo and artifacts
- [`docs/architecture.md`](docs/architecture.md) diagrams the local file-based detection workflow
- [`docs/event-time-model.md`](docs/event-time-model.md) defines event, observed, window, and artifact time semantics
- [`docs/vocabulary.md`](docs/vocabulary.md) defines the cross-demo evidence workflow terms and bounded correlation boundaries
- [`docs/sample-output.md`](docs/sample-output.md) summarizes the committed sample artifacts
- [`docs/roadmap.md`](docs/roadmap.md) defines the v1 reviewer contract stabilization phase
- [`data/processed/summary.json`](data/processed/summary.json) captures the default run in machine-readable form
- [`data/processed/richer_sample/summary.json`](data/processed/richer_sample/summary.json) captures the richer scenario pack
- [`tests/`](tests/) keeps regression coverage close to the CLI behavior and windowing logic

## v1 Reviewer Contract Stabilization

- demo expansion is closed
- v1.1 is an Operator Reproduction Release, not a new-demo release
- treat v1.0 as a five-demo contract freeze, not a feature expansion
- stabilize the five-demo matrix and avoid broad platform expansion
- freeze reviewer-visible artifact names unless a rename is intentionally coordinated across docs, tests, and sample outputs
- keep JSON schema contracts aligned with reviewer-facing JSON and JSONL evidence artifacts across the five-demo matrix
- keep committed artifacts aligned with regenerated pipeline output through `python scripts/regenerate_artifacts.py --check`
- add a reviewer-facing artifact diff for each release, using `no-artifact-change` when committed reviewer artifacts are unchanged
- use [`docs/reviewer-pack.md`](docs/reviewer-pack.md) and [`docs/architecture.md`](docs/architecture.md) as the consolidation entrypoints
- use the [`v1 readiness gate`](docs/v1-readiness-gate.md) before treating the repo as consolidated
- avoid additional demo expansion during v1 reviewer contract stabilization

## Scope

This repository is a local, reviewer-oriented detection workflow lab, not a production monitoring system.

## Limitations

- No real-time ingestion
- No streaming state management
- No alert routing or case management
- No dashboard or service deployment
- Sample-data driven only
