# Config-Change Investigation Reviewer Pack

This page describes the small, sanitized reviewer pack for `config-change-investigation-demo`.

Pack directory:

- `docs/reviewer-pack-v0.6.0/`

The pack is suitable for release attachment or offline review. All examples are representative sanitized examples aligned with the demo's synthetic sample semantics. They are non-production artifacts and do not contain secrets, machine-specific paths, or deployment claims.

## Pack Contents

| File | Path | What It Proves |
| --- | --- | --- |
| `MANIFEST.md` | artifact index | The pack scope, source type, and intended reviewer use |
| `benign-change-example.json` | benign change with no investigation | A benign config change remains visible in normalized input but does not become an investigation |
| `risky-change-with-evidence-example.json` | risky change with nearby evidence | A risky config change becomes an investigation and carries bounded supporting evidence |
| `bounded-case-no-evidence-example.json` | risky change with bounded case but no nearby evidence | A risky config change still produces an explicit investigation even when bounded correlation finds zero nearby evidence |
| `investigation-summary-example.json` | reduced summary path | The reduced summary stays deterministic and preserves the same evidence counts and bounded-correlation explanation |

## Benign Change With No Investigation

Relevant file:

- `docs/reviewer-pack-v0.6.0/benign-change-example.json`

Inspect:

- `change_event.config_key`
- `change_event.new_value`
- `reviewer_expectation.appears_in`
- `reviewer_expectation.not_expected_in`

Reviewer conclusion:

- A benign change is kept in normalized input context, but it does not match a risky-change rule and should not appear in `investigation_hits.json` or `investigation_summary.json`.

## Risky Change With Nearby Evidence

Relevant files:

- `docs/reviewer-pack-v0.6.0/risky-change-with-evidence-example.json`
- `docs/reviewer-pack-v0.6.0/investigation-summary-example.json`

Inspect:

- `investigation.rule_id`
- `investigation.correlation_window_minutes`
- `investigation.evidence_counts`
- `investigation.attached_policy_denials`
- `investigation.attached_follow_on_events`
- `summary_record.summary`

Reviewer conclusion:

- A deterministic risky-change rule creates an investigation, and bounded correlation attaches only nearby evidence that shares the same `target_system` and falls inside the configured window.

## Risky Change With Bounded Case But No Nearby Evidence

Relevant files:

- `docs/reviewer-pack-v0.6.0/bounded-case-no-evidence-example.json`
- `docs/reviewer-pack-v0.6.0/investigation-summary-example.json`

Inspect:

- `investigation.evidence_counts`
- `investigation.attached_policy_denials`
- `investigation.attached_follow_on_events`
- `investigation.bounded_correlation_reason`

Reviewer conclusion:

- A risky change stays explicit as an investigation even when bounded correlation finds zero nearby denials or follow-on events. The demo does not silently discard this case.
