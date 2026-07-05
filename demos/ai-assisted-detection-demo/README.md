# AI-Assisted Detection Demo

This demo is part of `telemetry-lab` and is intentionally framed as a portfolio-grade security engineering prototype.

It demonstrates constrained AI-assisted case drafting for SOC-style workflows, not autonomous detection or response.

It combines deterministic detections with a tightly constrained LLM stage:

- the rules decide which activity is interesting
- the grouping logic decides which hits belong in the same case
- the LLM is limited to structured summaries, likely causes, uncertainty notes, and suggested next steps

The LLM does **not** make final incident decisions, modify rules, call tools, or execute response actions. Human verification is always required.

## Purpose

The goal is to show a credible bridge between deterministic telemetry analytics and safe analyst assistance.

This is not an autonomous SOC. It is a constrained drafting pipeline that keeps rule logic, ATT&CK mapping, case grouping, and evidence handling deterministic.

For a no-run reviewer pack, see [docs/ai-assisted-detection-examples.md](../../docs/ai-assisted-detection-examples.md).

## Pipeline

1. ingest sample auth, web, and process events from JSONL
2. normalize them into a shared internal schema
3. apply deterministic detection rules
4. group rule hits into cases by shared entities and time proximity
5. attach ATT&CK mappings from rule metadata
6. build a case bundle with raw evidence, rule hits, severity, and evidence highlights
7. pass the case bundle to a constrained local demo LLM adapter with strict instruction and data separation
8. require JSON-only output against a local schema
9. validate the response and reject invalid output
10. emit analyst-facing artifacts and audit traces

## Guardrails

- telemetry content is marked as untrusted data
- system instructions are separated from the evidence payload
- the response must pass local JSON schema validation
- the response must pass a semantic validation layer after schema validation
- `human_verification` is required and must be `required`
- no external tool use is allowed in the LLM stage
- no automated response actions are allowed
- forbidden action-taking or final-verdict language is rejected and recorded
- summaries are rejected if the returned `case_id` does not exactly match the input case bundle
- a prompt-injection-like sample event is included and treated as telemetry, not instruction
- rejected summaries are fail-closed: they do not enter `case_summaries.json`
- accepted and rejected outcomes are both recorded in `audit_traces.jsonl`

## Quick start

From the repository root:

```bash
python -m pip install -e ".[dev]"
telemetry-lab run ai-assisted
```

Generated artifacts are written to `demos/ai-assisted-detection-demo/artifacts/`.

## Demo inputs

- sample data: `data/raw/sample_security_events.jsonl`
- deterministic rules: `config/rules.yaml`
- structured output schema: `config/llm_case_output_schema.json`

## Expected artifacts

- `artifacts/rule_hits.json`
- `artifacts/case_bundles.json`
- `artifacts/case_summaries.json`
- `artifacts/case_report.md`
- `artifacts/audit_traces.jsonl`
- `artifacts/run_manifest.json`

## Expected run summary

The bundled sample run should report:

- `15` raw events normalized into `15` internal events
- `5` deterministic rule hits
- `3` grouped cases
- `3` accepted JSON summaries
- `0` rejected summaries in the default accepted path
- `3` audit records

## Artifact semantics

- `rule_hits.json`: deterministic rule hits with rule metadata, ATT&CK mapping, entities, and evidence highlights
- `case_bundles.json`: grouped cases with severity, rule hits, ATT&CK mappings, raw evidence, and untrusted-data marking
- `case_summaries.json`: only accepted JSON summaries that passed schema and semantic validation
- `case_report.md`: analyst-facing report with run counts, accepted summaries, and explicit notes for rejected case summaries
- `case_report.md`: includes a top-level run integrity section that surfaces rule/config degradation
- `audit_traces.jsonl`: stable per-record audit log for accepted and rejected paths, using `schema_version = ai-assisted-detection-audit/v1` and including `ts`, `case_id`, `validation_status`, `rejection_reason`, `rule_ids`, `prompt_input_digest`, `evidence_digest`, and bounded response excerpts
- `run_manifest.json`: synthetic-local run manifest with tool version, input/config digests, and artifact schema versions

## Rejection behavior

- non-JSON or malformed JSON responses are rejected and recorded
- missing required fields or invalid enum values are rejected and recorded
- schema-valid summaries with the wrong `case_id` are rejected and recorded
- action-taking language is rejected
- final-verdict or confirmed-compromise language is rejected
- malformed rule or ATT&CK metadata is rejected before detection logic uses it

Rejected outputs do not become analyst summaries. Analysts can still inspect deterministic evidence through `case_bundles.json`, `case_report.md`, and `audit_traces.jsonl`.

## Reviewer walkthrough

### Accepted summary path

Use the default sample run artifacts in `artifacts/case_summaries.json`, `artifacts/case_report.md`, and `artifacts/audit_traces.jsonl`.

Verify that `CASE-001` appears in all three places, that the `case_id` matches exactly, that `human_verification` is `required`, and that the audit record shows `validation_status = accepted` with `schema_version = ai-assisted-detection-audit/v1`.

### Rejected summary path

Run:

```bash
pytest tests/test_ai_assisted_detection_demo.py -k "audit_traces_capture_accepted_and_rejected_paths or case_id_mismatch" --basetemp .pytest-artifacts-ai-demo-rejections
```

Then inspect the `case_report.md`, `case_summaries.json`, and `audit_traces.jsonl` files under `.pytest-artifacts-ai-demo-rejections/test_*/artifacts/`.

Verify that the rejected case is absent from `case_summaries.json`, appears in `case_report.md` as `Summary status: rejected`, and has an audit record with `validation_status = rejected` plus a concrete `rejection_reason` such as `missing_required_fields`, `semantic_validation_failed`, or `case_id_mismatch`.

### Degraded coverage path

Run:

```bash
pytest tests/test_ai_assisted_detection_demo.py -k malformed_attack_metadata_is_rejected_and_recorded --basetemp .pytest-artifacts-ai-demo-degraded
```

Then inspect the generated `case_report.md` and `audit_traces.jsonl` files under `.pytest-artifacts-ai-demo-degraded/test_*/artifacts/`.

Verify that `case_report.md` exposes `## Run Integrity`, `coverage_degraded: yes`, and the rejected rule id, and that `audit_traces.jsonl` contains a global rejection record with `case_id = null` and `rejection_reason = rule_metadata_validation_failed`.

## Limitations

- the LLM stage is a constrained local demo adapter, not a production model integration
- detections are intentionally small and rule-based
- grouping is simple and optimized for readability over recall
- sample telemetry is synthetic and limited in volume
- there is no ticketing, SOAR, sandboxing, or live data ingestion
- artifacts are for analyst review only and do not represent final incident disposition
- rejection logic is intentionally conservative and favors fail-closed behavior over model flexibility
