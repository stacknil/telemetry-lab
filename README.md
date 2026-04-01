# telemetry-lab

[![CI](https://github.com/stacknil/telemetry-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/stacknil/telemetry-lab/actions/workflows/ci.yml)

Small portfolio prototypes for telemetry analytics, monitoring, and detection-oriented signal processing.

Latest milestone: [v0.5.0 — third demo and three-demo structure](https://github.com/stacknil/telemetry-lab/releases/latest).

## Demos

- [telemetry-window-demo](#telemetry-window-demo)
- [ai-assisted-detection-demo](demos/ai-assisted-detection-demo/README.md)
- [rule-evaluation-and-dedup-demo](demos/rule-evaluation-and-dedup-demo/README.md)

| Demo | Input | Deterministic core | LLM role | Main artifacts | Guardrails / non-goals |
| --- | --- | --- | --- | --- | --- |
| [telemetry-window-demo](#telemetry-window-demo) | JSONL / CSV events | Windows<br>Features<br>Alert thresholds | None | `features.csv`<br>`alerts.csv`<br>`summary.json`<br>3 PNG plots | MVP only<br>No realtime<br>No case management |
| [ai-assisted-detection-demo](demos/ai-assisted-detection-demo/README.md) | JSONL auth / web / process | Normalize<br>Rules<br>Grouping<br>ATT&CK mapping | JSON-only case drafting | `rule_hits.json`<br>`case_bundles.json`<br>`case_summaries.json`<br>`case_report.md`<br>`audit_traces.jsonl` | Human verification required<br>No autonomous response<br>No final verdict |
| [rule-evaluation-and-dedup-demo](demos/rule-evaluation-and-dedup-demo/README.md) | JSON raw rule hits | Scope resolution<br>Cooldown grouping<br>Suppression reasoning | None | `rule_hits_before_dedup.json`<br>`rule_hits_after_dedup.json`<br>`dedup_explanations.json`<br>`dedup_report.md` | No realtime<br>No dashboard<br>No AI stage |

## What This Repo Is

`telemetry-lab` is a small portfolio repository for telemetry analytics and constrained detection-oriented workflows. It is organized as three local, file-based demos that are reproducible from committed sample data and intentionally scoped for public review rather than production use.

### telemetry-window-demo

`telemetry-window-demo` turns timestamped event streams into sliding-window feature tables, cooldown-reduced rule-based alerts, PNG timeline plots, and machine-readable run summaries.

### ai-assisted-detection-demo

`ai-assisted-detection-demo` uses deterministic normalization, detection, case grouping, and ATT&CK mapping, then limits the LLM to JSON-only case summarization. Human verification is required, there is no autonomous response, and the demo does not produce a final incident verdict.

### rule-evaluation-and-dedup-demo

`rule-evaluation-and-dedup-demo` starts from raw rule hits and makes cooldown behavior legible. It shows which hits were kept, which were suppressed, how scope was resolved, and why repeated hits collapsed into fewer retained alerts.

## Quick Run

```bash
python -m pip install -e .
python -m telemetry_window_demo.cli run --config configs/default.yaml
```

Other demo entrypoints:

- `python -m telemetry_window_demo.cli run-ai-demo`
- `python -m telemetry_window_demo.cli run-rule-dedup-demo`

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

- [`demos/rule-evaluation-and-dedup-demo/README.md`](demos/rule-evaluation-and-dedup-demo/README.md) explains the third demo and links its committed before/after dedup artifacts
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
