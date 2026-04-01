# Config-Change Investigation Demo

## Problem

The repository already shows windowed alerting and post-detection deduplication. What it does not yet show is a compact investigation flow for risky configuration changes that lead to observable follow-on effects. A small config-change demo would make that path legible without turning the repo into a broader platform.

## Sample Inputs

- JSONL configuration change events with fields such as `timestamp`, `actor`, `target_system`, `config_key`, `old_value`, `new_value`, and `change_result`
- JSONL policy or access-denial events tied to the same systems or actors
- JSONL follow-on telemetry such as auth failures, service restarts, or rule hits that occur shortly after the change

The initial sample should stay synthetic, local, and small enough to review in one sitting.

## Deterministic Core

- Normalize config-change, denial, and follow-on events into one shared internal schema
- Detect a narrow set of risky changes with explicit deterministic rules
- Correlate nearby follow-on events by shared entities and bounded time proximity
- Produce a concise machine-readable investigation summary with no model-generated reasoning
- Keep correlation logic file-based, replayable, and easy to inspect from committed sample data

## Artifacts

- `change_events_normalized.json`
- `investigation_hits.json`
- `investigation_summary.json`
- `investigation_report.md`

The report should explain which configuration change was flagged, what nearby evidence was attached, and why the final summary stayed bounded.

## Non-Goals

- No realtime ingestion
- No service deployment
- No dashboard
- No autonomous response or remediation
- No new AI stage unless a later brief clearly justifies one
- No production-ready change-management workflow

## Acceptance Criteria

- A reviewer can follow one risky configuration change from raw input to investigation summary without reading code
- The sample data is committed, reproducible, and small enough for artifact-level review
- Correlation stays deterministic and auditable
- The artifacts clearly distinguish the triggering change from attached follow-on evidence
- The demo remains local, file-based, and portfolio-oriented
