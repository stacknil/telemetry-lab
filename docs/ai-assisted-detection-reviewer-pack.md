# AI-Assisted Detection Reviewer Pack

This page describes the small, sanitized reviewer pack for `ai-assisted-detection-demo`.

Pack directory:

- `docs/reviewer-pack-v0.4.0/`

The pack is suitable for attaching to the existing `v0.4.0` release or downloading for offline review. It does not contain secrets, machine-specific paths, or production claims.

## Pack Contents

| File | Path | What It Proves |
| --- | --- | --- |
| `MANIFEST.md` | artifact index | The pack scope, source type, and intended reviewer use |
| `accepted-summary-example.json` | accepted path | Accepted output stays constrained and is auditable |
| `rejected-summary-example.json` | rejected path | Rejected output is fail-closed and still recorded |
| `degraded-coverage-example.json` | degraded coverage path | Rule metadata failure is surfaced without changing demo semantics |

## Accepted Path

Relevant file:

- `docs/reviewer-pack-v0.4.0/accepted-summary-example.json`

Inspect:

- `case_id`
- `human_verification`
- `scope_guardrail`
- `audit_record.validation_status`

Reviewer conclusion:

- Accepted summaries remain bounded to real cases and keep the same operator-review constraints as the demo itself.

## Rejected Path

Relevant file:

- `docs/reviewer-pack-v0.4.0/rejected-summary-example.json`

Inspect:

- `summary_status`
- `rejection_reason`
- `audit_record.validation_status`

Reviewer conclusion:

- Disallowed or mismatched model output is rejected rather than cleaned up or silently accepted.

## Degraded Coverage Path

Relevant file:

- `docs/reviewer-pack-v0.4.0/degraded-coverage-example.json`

Inspect:

- `run_integrity.coverage_degraded`
- `run_integrity.rejected_rules`
- `audit_record.case_id`
- `audit_record.rejection_reason`

Reviewer conclusion:

- Rule-metadata failure degrades coverage safely and is disclosed in reviewer-facing artifacts.

