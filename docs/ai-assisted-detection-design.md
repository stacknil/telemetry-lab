# AI-Assisted Detection Design

## Overview

`ai-assisted-detection-demo` is a constrained case-drafting pipeline inside `telemetry-lab`.

The deterministic pipeline ingests sample security telemetry, normalizes it into a shared schema, applies fixed detection rules, groups nearby hits into cases, and attaches ATT&CK metadata from rule configuration. The LLM stage is limited to structured summarization over a prepared case bundle. It does not decide whether an incident occurred, it does not change detections, and it does not execute actions.

## Threat Model And Non-Goals

The primary trust boundary is between system instructions and telemetry-derived evidence. Telemetry is treated as untrusted data because it may contain prompt-injection-like text, malformed fields, or misleading context. Rule configuration is also validated as input rather than assumed trustworthy.

Non-goals:

- autonomous investigation
- final incident verdicts
- automated containment, blocking, disabling, revocation, or isolation
- external tool execution
- rule tuning or model-driven detection decisions

## Case Bundle Schema

Each case bundle is deterministic and is built before any LLM call. The bundle contains:

- `case_id`
- `telemetry_classification` set to `untrusted_data`
- `first_seen` and `last_seen`
- `severity`
- `entities`
- `rule_hits`
- `attack_mappings`
- `evidence_highlights`
- `raw_evidence`

`rule_hits` are derived from deterministic rules only. `attack_mappings` are copied from validated rule metadata. `raw_evidence` remains untrusted telemetry and is never promoted into instructions.

## LLM Input Contract

The LLM input envelope contains three parts:

- system instructions
- response schema
- evidence payload

System instructions are fixed by code and carry the guardrails. The evidence payload contains the case bundle and explicitly labels telemetry as untrusted data. The prompt input is digested for audit purposes, but the audit log does not rely only on raw prompt dumps.

## LLM Output Schema

The accepted output is JSON only and must match the local schema version `ai-assisted-case-summary/v1`.

Required fields:

- `case_id`
- `summary`
- `likely_causes`
- `uncertainty_notes`
- `suggested_next_steps`
- `human_verification`
- `scope_guardrail`

`human_verification` must equal `required`. The schema is necessary but not sufficient; semantic validation runs after JSON/schema validation.

## Lifecycle Contract

Audit records use schema version `ai-assisted-detection-audit/v1`.

Accepted summary:

- one validated entry is written to `case_summaries.json`
- the matching case section in `case_report.md` includes the accepted summary text
- one audit record is written with `validation_status = accepted`

Rejected summary:

- no entry is written to `case_summaries.json`
- the matching case section in `case_report.md` is still emitted and marked as rejected or unavailable
- one audit record is written with `validation_status = rejected` and a concrete `rejection_reason`

## Guardrails

The pipeline enforces these controls:

- deterministic detection and case grouping happen before the LLM
- telemetry remains marked as untrusted data
- instructions and evidence are separated
- JSON parsing is fail-closed
- schema validation is fail-closed
- semantic validation rejects action-taking language and final-verdict language
- accepted summaries require `human_verification = required`
- no external tool use
- no automated response actions
- no final incident verdict

Semantic rejection is intentionally conservative. If the output suggests containment, disabling, blocking, isolation, revocation, or confirmed compromise, it is rejected.
Summaries are also rejected if the returned `case_id` does not exactly match the input case bundle.

## Failure Handling

The pipeline records both accepted and rejected paths in `audit_traces.jsonl`.

Explicit rejection classes include:

- `non_json_output`
- `json_parse_failure`
- `case_id_mismatch`
- `missing_required_fields`
- `invalid_enum_value`
- `schema_validation_failed`
- `semantic_validation_failed`
- `rule_metadata_validation_failed`
- `case_bundle_validation_failed`
- `model_generation_failed`

Rejected summaries do not enter `case_summaries.json`. The analyst-facing report still shows the case and notes that summarization was rejected, so rejected cases are not silently dropped.

Malformed rule metadata is rejected before the rule is used. This prevents hard crashes from blind indexing into ATT&CK metadata.

## Artifacts And Audit Trace Semantics

Artifacts:

- `rule_hits.json`: deterministic rule hit records
- `case_bundles.json`: deterministic grouped cases prepared for analyst review and optional summarization
- `case_summaries.json`: accepted summaries only
- `case_report.md`: analyst-facing view of accepted summaries plus explicit rejection notes
- `audit_traces.jsonl`: stable audit log for accepted and rejected validation paths

Each audit record includes stable review fields:

- `ts`
- `case_id`
- `schema_version`
- `output_schema_version`
- `stage`
- `validation_status`
- `rejection_reason`
- `rule_ids`
- `prompt_input_digest`
- `evidence_digest`
- `raw_response_excerpt`
- `validation_errors`
- `telemetry_classification`

`ts` is derived deterministically from the event context for reproducible demo output. `prompt_input_digest` and `evidence_digest` provide stable linkage without requiring the audit file to store only raw prompt envelopes.

The analyst-facing report also includes a run integrity section with accepted rules, rejected rules, whether coverage was degraded, and rejection reasons. This is used to surface global rule/config failures that are not tied to a single case.
