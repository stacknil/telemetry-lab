# Event Time Model

`telemetry-lab` keeps event, observation, window, and artifact times separate so local detection demos remain reproducible and auditable.

This model is informed by the OpenTelemetry Logs Data Model distinction between `Timestamp` and `ObservedTimestamp`: `Timestamp` represents when the event occurred at the source, while `ObservedTimestamp` represents when a collection system observed it. OpenTelemetry recommends using `Timestamp` first when exporting to a format with only one timestamp, falling back to `ObservedTimestamp` only when `Timestamp` is missing.

`telemetry-lab` is not an OpenTelemetry implementation. The terms below define how this repository names and interprets time in sample inputs, generated features, alerts, reports, and future demo artifacts.

## Fields

| Field | Meaning | Used for detection ordering? | Current repository mapping |
| --- | --- | --- | --- |
| `event_time` | Time the source event happened. | Yes | The default input column is named `timestamp`; configs may use `time.timestamp_col` to point at a source column such as `event_time`. |
| `observed_time` | Time a collector, loader, or intermediary observed the event. | No, unless a demo explicitly documents fallback behavior. | Optional future input or artifact field. Current core demos do not require it. |
| `window_start` / `window_end` | Deterministic analysis interval derived from `event_time`. | Yes | Feature rows, alert rows, and dedup artifacts use these boundaries. Windows are treated as `[window_start, window_end)`. |
| `artifact_generated_at` | Time an output artifact was rendered or written. | No | Optional provenance metadata for reports, summaries, or reviewer packs. It must not be used as event evidence. |

## Rules

- Prefer `event_time` for ordering, windowing, cooldown reasoning, and evidence correlation.
- Treat the current `timestamp` input column as `event_time` unless a config names another column through `time.timestamp_col`.
- Preserve `observed_time` when a source provides it, but keep it separate from event ordering.
- If a downstream export format only supports one timestamp, use `event_time` when present; fall back to `observed_time` only when the source event time is unavailable.
- Derive `window_start` and `window_end` from event time, not from artifact generation time.
- Use `artifact_generated_at` only for provenance and reproducibility checks.

## Why It Matters

Detection workflows become hard to review when ingestion time, source event time, analysis-window time, and report-generation time collapse into one ambiguous `timestamp`. This repository keeps those concepts explicit:

- raw event records carry source event time
- feature rows and alerts carry deterministic window boundaries
- reports may carry artifact generation metadata
- reviewer evidence can be checked without guessing which clock controlled the decision

## References

- [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
