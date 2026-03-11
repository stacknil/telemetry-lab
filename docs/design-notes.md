# Design Notes

## Objective

Build a minimum credible telemetry asset, not a large platform. The repository should prove that timestamped event streams can be transformed into window-level features and alert-oriented outputs.

The design target is a bridge project: strong enough to read like a small monitoring prototype, but narrow enough to stay understandable and runnable for a single developer.

## Architecture

The implementation follows a narrow pipeline:

1. `io.py` loads JSONL or CSV inputs and validates required fields.
2. `preprocess.py` normalizes timestamps and categorical values.
3. `windowing.py` builds sliding windows over sorted events.
4. `features.py` computes per-window telemetry features.
5. `rules.py` turns features into rule-based alerts.
6. `visualize.py` renders operator-facing PNG outputs.
7. `cli.py` wires the pipeline into `run`, `summarize`, and `plot`.

## Design tradeoffs

- `pandas` is used for clarity and concise feature computation.
- Rules stay threshold-based to emphasize detection semantics over model complexity.
- Relative config paths are resolved from the repository root when the config lives under `configs/`.
- Outputs are CSV and PNG because they are easy to inspect, diff, and embed in README material.
- The notebook remains intentionally tiny so the packaged CLI pipeline stays the primary entrypoint.

## Non-goals

- distributed stream processing
- live ingestion from production systems
- durable storage
- dashboard hosting
- production alert delivery
