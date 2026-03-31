# AI-Assisted Detection Examples

This page is a small, sanitized examples pack for reviewers who want to inspect `ai-assisted-detection-demo` without running the pipeline.

The accepted path points to committed demo artifacts. The rejected and degraded-coverage paths use representative sanitized excerpts that match the fields emitted by the pipeline and exercised by tests.

## Accepted Summary Path

**Artifact files**

- `demos/ai-assisted-detection-demo/artifacts/case_summaries.json`
- `demos/ai-assisted-detection-demo/artifacts/case_report.md`
- `demos/ai-assisted-detection-demo/artifacts/audit_traces.jsonl`

**Fields to inspect**

- `case_summaries.json`: `case_id`, `human_verification`, `scope_guardrail`
- `case_report.md`: `Summary`, `Likely causes`, `Suggested next steps`
- `audit_traces.jsonl`: `validation_status`, `schema_version`, `rejection_reason`

```json
{
  "case_id": "CASE-001",
  "human_verification": "required",
  "scope_guardrail": "no_final_incident_decision|no_rule_changes|no_automated_actions"
}
```

```json
{
  "case_id": "CASE-001",
  "schema_version": "ai-assisted-detection-audit/v1",
  "validation_status": "accepted",
  "rejection_reason": null
}
```

**What the reviewer should conclude**

- The accepted summary is bound to a real deterministic case and recorded in both analyst-facing and audit artifacts.
- The summary remains constrained draft output: `human_verification` is required and the scope guardrail forbids final verdicts, rule changes, and automated actions.

## Rejected Summary Path

**Artifact files**

- `case_summaries.json`
- `case_report.md`
- `audit_traces.jsonl`

**Fields to inspect**

- `case_summaries.json`: absence of the rejected `case_id`
- `case_report.md`: `Summary status`, `Rejection reason`, analyst note
- `audit_traces.jsonl`: `case_id`, `validation_status`, `rejection_reason`

Representative sanitized excerpt:

```json
{
  "case_id": "CASE-EX-REJECTED",
  "validation_status": "rejected",
  "rejection_reason": "case_id_mismatch"
}
```

```md
## CASE-EX-REJECTED

Summary status: rejected
Rejection reason: case_id_mismatch
Analyst note: no accepted summary was produced for this case; rely on deterministic evidence.
```

**What the reviewer should conclude**

- Invalid or disallowed model output is rejected fail-closed rather than patched or silently accepted.
- The rejection is auditable, and deterministic evidence remains available even when no accepted summary exists.

## Degraded Coverage Path

**Artifact files**

- `case_report.md`
- `audit_traces.jsonl`

**Fields to inspect**

- `case_report.md`: `accepted_rules`, `rejected_rules`, `coverage_degraded`, `rejection_reasons`
- `audit_traces.jsonl`: `case_id = null`, `rule_ids`, `rejection_reason`

Representative sanitized excerpt:

```md
## Run Integrity

- accepted_rules: AUTH-002, PROC-001, WEB-001
- rejected_rules: AUTH-001
- coverage_degraded: yes
- rejection_reasons: rule_metadata_validation_failed

Global validation rejections:
- AUTH-001: rule_metadata_validation_failed
```

```json
{
  "case_id": null,
  "rule_ids": ["AUTH-001"],
  "validation_status": "rejected",
  "rejection_reason": "rule_metadata_validation_failed"
}
```

**What the reviewer should conclude**

- Rule or ATT&CK metadata failures reduce coverage safely instead of causing a hard crash.
- The coverage loss is disclosed in the main report, not hidden only in the audit log.
