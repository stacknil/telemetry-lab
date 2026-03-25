# telemetry-lab

[![CI](https://github.com/stacknil/telemetry-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/stacknil/telemetry-lab/actions/workflows/ci.yml)

Small portfolio prototypes for telemetry analytics, monitoring, and detection-oriented signal processing.

## What This Repo Is

`telemetry-window-demo` is a local Python CLI that turns timestamped event streams into:

- sliding-window feature tables
- cooldown-reduced rule-based alerts
- PNG timeline plots
- machine-readable run summaries

## Quick Run

```bash
python -m pip install -e .
python -m telemetry_window_demo.cli run --config configs/default.yaml
```

That command reads `data/raw/sample_events.jsonl` and regenerates:

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

- `timestamp`
- `event_type`
- `source`
- `target`
- `status`

Cooldown behavior:

- repeated alerts are keyed by `(rule_name, scope)`
- scope prefers the first available entity-like field in this order: `entity`, `source`, `target`, `host`
- when no entity-like field is present, cooldown falls back to per-`rule_name` behavior

## Repo Guide

- [`docs/sample-output.md`](docs/sample-output.md) summarizes the committed sample artifacts
- [`docs/roadmap.md`](docs/roadmap.md) sketches the next demo directions
- [`data/processed/summary.json`](data/processed/summary.json) captures the default run in machine-readable form
- [`data/processed/richer_sample/summary.json`](data/processed/richer_sample/summary.json) captures the richer scenario pack
- [`tests/`](tests/) keeps regression coverage close to the CLI behavior and windowing logic

## Next Demo Directions

- strengthen JSONL and CSV validation so ingestion failures are clearer
- keep reducing repeated alert noise while preserving simple rule-based behavior
- keep sample-output docs and public repo presentation aligned with the checked-in demo state

## Scope

This repository is a portfolio prototype, not a production monitoring system.

## Limitations

- No real-time ingestion
- No streaming state management
- No alert routing or case management
- No dashboard or service deployment
- Sample-data driven only
