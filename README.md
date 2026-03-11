# telemetry-lab

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

## Current behavior

- Input: JSONL event stream with required fields `timestamp`, `event_type`, `source`, `target`, `status`
- Windowing: 60 second sliding windows with 10 second step
- Features: event count, error count, error rate, unique source and target counts, high severity count, plus selected event-type counts
- Rules: high error rate, login fail burst, high severity spike, persistent high error, source spread spike, and repeated rare events
- Visualization: event count timeline, error rate timeline, and alert timeline

With the bundled sample data, the default run currently produces:

- `41` normalized events
- `24` windows
- `53` alerts

## Outputs

Running the default command regenerates:

- `data/processed/features.csv`
- `data/processed/alerts.csv`
- `data/processed/event_count_timeline.png`
- `data/processed/error_rate_timeline.png`
- `data/processed/alerts_timeline.png`

## Scope

This repository is a portfolio prototype, not a production monitoring system.

## Limitations

- No real-time ingestion
- No streaming state management
- No alert routing or case management
- No dashboard or service deployment
- Sample-data driven only
