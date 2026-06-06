# Reviewer brief

## Problem

Telemetry and detection projects often look impressive in screenshots but are hard to review end to end. Reviewers need a narrow, reproducible path from raw events to outputs without a production stack or opaque AI behavior.

## What it does

`telemetry-lab` is a local, file-based portfolio repo with four demos:

- `telemetry-window-demo` for sliding-window features and rule-based alerts
- `ai-assisted-detection-demo` for deterministic case grouping plus bounded JSON-only LLM drafting
- `rule-evaluation-and-dedup-demo` for cooldown and suppression reasoning
- `config-change-investigation-demo` for risky-change evidence correlation

## Reviewer Evidence

- Reproducible command: `python -m telemetry_window_demo.cli run --config configs/default.yaml`
- Deterministic outputs: feature tables, alert tables, `summary.json`, PNG timelines, dedup reports, investigation reports, and bounded AI case reports.
- Tests / CI: pytest coverage for windowing, CLI behavior, demo pipelines, artifact validation, and deterministic guardrails; GitHub Actions CI is enabled.
- Release evidence: reviewer packs and release notes through the current `v0.6.0` milestone.
- Non-goals: production monitoring, real-time ingestion, alert routing, autonomous response, dashboards, or final incident verdicts.

## Quick run

```bash
python -m pip install -e ".[dev]"
python -m telemetry_window_demo.cli run --config configs/default.yaml
python -m telemetry_window_demo.cli run-rule-dedup-demo
python -m telemetry_window_demo.cli run-config-change-demo
python -m telemetry_window_demo.cli run-ai-demo
```

## Sample output

The default `run --config configs/default.yaml` path regenerates:

- `data/processed/features.csv`
- `data/processed/alerts.csv`
- `data/processed/summary.json`
- three PNG timelines under `data/processed/`

The current committed default sample reports:

- `41` normalized events
- `24` windows
- `12` alerts after a `60` second cooldown

The other demos emit reviewer-facing artifacts such as `dedup_report.md`, `investigation_report.md`, and `case_report.md`.

## What this proves

- telemetry normalization and windowed feature design
- alert logic that stays reviewable instead of disappearing into scoring
- bounded, explicitly non-autonomous AI use
- reviewer-friendly artifact generation across multiple demo shapes

## Safety / boundaries

- local sample-data workflows only
- no real-time ingestion or autonomous response
- no final incident verdicts from the AI-assisted demo
- public review focus, not production deployment claims

## Limitations

- no alert routing, dashboarding, or case management
- sample-data driven, not connected to live systems
- no streaming state management
- intentionally small-scope detection workflow demos rather than a unified monitoring platform

## Next milestone

Consolidate the current reviewer path for v0.7 / v1.0: keep the demo matrix stable, freeze reviewer-visible artifact names, maintain one top-level reviewer pack, and keep the architecture diagram aligned with actual CLI and artifact behavior.
