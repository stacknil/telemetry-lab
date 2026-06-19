# Cross-Demo Vocabulary

This vocabulary defines the reviewer-facing terms used across `telemetry-lab`.
It is a local evidence workflow vocabulary, not a SIEM object model, not a
case-management lifecycle, and not an incident response taxonomy.

## Term Ladder

| Term | Meaning in this repo | Typical artifacts | What it is not |
| --- | --- | --- | --- |
| `event` | A source or normalized telemetry record that says something happened at a specific time. Events are the raw material for windowing, rule evaluation, and bounded correlation. | `data/raw/*.jsonl`, `change_events_normalized.json`, `normalized_cloudtrail_events.json` | A detection by itself, an alert verdict, or a final incident conclusion. |
| `signal` | A deterministic correlation output that selects one or more events for review because they match bounded investigation logic. Signals usually carry evidence IDs, actor or entity context, and a reason. | `investigation_signals.json` | A live alert route, autonomous action, or proof of compromise. |
| `hit` | A rule-evaluation occurrence. A hit can be a raw rule match, a retained alert candidate, or a suppressed duplicate depending on the demo stage. | `rule_hits.json`, `rule_hits_before_dedup.json`, `rule_hits_after_dedup.json`, `investigation_hits.json` | A fully investigated finding or a case-management ticket. |
| `finding` | A reviewer-facing observation derived from hits or signals and tied back to evidence. Findings may appear in prose reports, but they must remain bounded by the committed artifacts. | `case_report.md`, `dedup_report.md`, `investigation_report.md` | A final incident verdict, root-cause statement, or production severity decision. |
| `case_bundle` | A bounded evidence package passed into the AI-assisted drafting stage. It groups rule hits, raw evidence, entities, severity, and ATT&CK mapping for one deterministic case candidate. | `case_bundles.json` | A persistent case record, workflow queue item, or incident-management object. |
| `summary` | A compact machine-readable aggregate of counts, selected outcomes, and run metadata. Summaries should be easy for tests and reviewers to parse. | `summary.json`, `case_summaries.json`, `investigation_summary.json` | A narrative report or a substitute for inspecting evidence artifacts. |
| `report` | A human-readable Markdown explanation of the demo output. Reports are review aids that point back to deterministic JSON, JSONL, CSV, or Markdown evidence. | `case_report.md`, `dedup_report.md`, `investigation_report.md` | The canonical machine contract or an operational dashboard. |
| `audit_trace` | A JSONL audit record of constrained processing decisions, especially guardrails around AI-assisted drafting. It records inputs, validation, and accept/reject outcomes without exposing model chain-of-thought. | `audit_traces.jsonl` | Free-form reasoning logs, private credentials, prompts containing private data, or autonomous decision authority. |

## How the Terms Flow

The demos do not all use every term, but they follow the same evidence shape:

1. `event`: committed sample input or normalized telemetry.
2. `hit` or `signal`: deterministic rule or correlation output.
3. `case_bundle`: bounded grouping when an AI-assisted drafting stage exists.
4. `summary`: machine-readable aggregate for checks and reviewers.
5. `report`: human-readable explanation tied to the underlying artifacts.
6. `audit_trace`: guardrail and validation trail for constrained AI behavior.

This flow is intentionally narrower than a production monitoring platform. It
keeps the repo focused on reproducible evidence generation and review.

## Naming Rules

- Use `event` for source facts or normalized facts.
- Use `hit` for rule matches and cooldown/suppression reasoning.
- Use `signal` for bounded investigation outputs that correlate multiple events.
- Use `finding` only for reviewer-facing observations backed by artifact IDs.
- Use `case_bundle` only for bounded AI-assisted case drafting inputs.
- Use `summary` for machine-readable aggregates.
- Use `report` for human-readable Markdown explanations.
- Use `audit_trace` for structured guardrail, validation, and provenance records.

## Time Semantics

Events, hits, signals, summaries, and reports should preserve the time semantics
defined in [`docs/event-time-model.md`](event-time-model.md). In short:

- `event_time` is when the source event happened.
- `observed_time` is when a collector or pipeline observed it, when available.
- `window_start` and `window_end` define feature-window boundaries.
- `artifact_generated_at` is when a local artifact was generated.

Do not use a later summary, report, or audit timestamp to rewrite the source
event order.

## Contract Boundaries

This vocabulary should make demo artifacts easier to compare across the repo,
but it does not add production platform claims. The repo still has:

- no real-time ingestion
- no alert routing
- no dashboard or case-management service
- no autonomous response
- no final incident verdicts
