# telemetry-lab

[![CI](https://github.com/stacknil/telemetry-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/stacknil/telemetry-lab/actions/workflows/ci.yml)

Small prototypes for telemetry analytics, monitoring, and detection-oriented signal processing.

## Current demo

`telemetry-window-demo` turns timestamped event streams into sliding-window telemetry features, simple rule-based alerts, and operator-friendly CSV and PNG outputs.

## MVP workflow

1. Install the package and its minimal dependencies:

   ```bash
   python -m pip install -e .
   ```

2. Run the bundled sample pipeline end-to-end:

   ```bash
   python -m telemetry_window_demo.cli run --config configs/default.yaml
   ```

The sample config reads `data/raw/sample_events.jsonl` and regenerates outputs in `data/processed/`.

For a richer scenario pack that is easier to walk through in demos:

```bash
python -m telemetry_window_demo.cli run --config configs/richer_sample.yaml
```

That scenario pack reads `data/raw/richer_sample_events.jsonl` and writes outputs to `data/processed/richer_sample/`.
It currently produces `28` normalized events, `24` windows, and `8` alerts.
Both sample paths also emit a compact `summary.json` alongside the CSV and PNG outputs.

## Current behavior

Default sample input:

- JSONL event stream under `data/raw/sample_events.jsonl`

Runtime input support:

- `.jsonl` (default sample/demo format)
- `.csv` (also supported by the loader)

Required fields for both formats on every row/record:

- `timestamp`
- `event_type`
- `source`
- `target`
- `status`

With the bundled sample data, the default run currently produces:

- `41` normalized events
- `24` windows
- `12` alerts after applying a `60` second cooldown

The default config suppresses repeated alerts by cooldown key. The key is `rule_name` plus an entity scope when the rule input includes `entity`, `source`, `target`, or `host`; otherwise it falls back to `rule_name` alone. Different cooldown keys can still alert on the same window.

The richer scenario pack uses a longer `120` second cooldown so the output stays compact enough to inspect as four phases: normal background activity, a login-failure burst, a high-risk configuration change with follow-on policy denials, and a rare malware-alert repeat sequence.

## Outputs

Running the default command regenerates:

- `data/processed/features.csv`
- `data/processed/alerts.csv`
- `data/processed/summary.json`
- `data/processed/event_count_timeline.png`
- `data/processed/error_rate_timeline.png`
- `data/processed/alerts_timeline.png`

The summary artifact includes the input path, output directory, normalized event count, window count, feature row count, alert count, triggered rule names and counts, cooldown setting, and generated artifact paths.

## Scope

This repository is a portfolio prototype, not a production monitoring system.

## Limitations

- No real-time ingestion
- No streaming state management
- No alert routing or case management
- No dashboard or service deployment
- Sample-data driven only
