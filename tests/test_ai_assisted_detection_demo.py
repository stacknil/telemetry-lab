from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from telemetry_window_demo.ai_assisted_detection_demo import default_demo_root, run_demo
from telemetry_window_demo.ai_assisted_detection_demo.llm import DemoStructuredCaseLlm
from telemetry_window_demo.ai_assisted_detection_demo.pipeline import (
    JsonOutputError,
    SchemaValidationError,
    SemanticValidationError,
    apply_detection_rules,
    build_case_bundles,
    build_prompt_envelope,
    group_rule_hits,
    load_json,
    load_jsonl,
    load_yaml,
    normalize_events,
    parse_and_validate_json_output,
)


class ScriptedLlm:
    def __init__(self, responses: list[Any]) -> None:
        self._responses = list(responses)
        self._index = 0

    def generate(self, system_instructions: str, evidence_payload: dict[str, Any]) -> str:
        if self._index >= len(self._responses):
            factory = self._responses[-1]
        else:
            factory = self._responses[self._index]
        self._index += 1

        if callable(factory):
            return factory(system_instructions, evidence_payload)
        return factory


def _demo_inputs():
    demo_root = default_demo_root()
    raw_events = load_jsonl(demo_root / "data" / "raw" / "sample_security_events.jsonl")
    rules_config = load_yaml(demo_root / "config" / "rules.yaml")
    output_schema = load_json(demo_root / "config" / "llm_case_output_schema.json")
    normalized_events = normalize_events(raw_events)
    rule_hits = apply_detection_rules(normalized_events, rules_config["rules"])
    grouped_cases = group_rule_hits(
        rule_hits,
        gap_minutes=int(rules_config["case_grouping"]["gap_minutes"]),
    )
    case_bundles = build_case_bundles(
        grouped_cases,
        normalized_events,
        context_minutes=int(rules_config["case_grouping"]["context_minutes"]),
    )
    return demo_root, output_schema, normalized_events, rule_hits, grouped_cases, case_bundles


def _accepted_response(_: str, evidence_payload: dict[str, Any]) -> str:
    return DemoStructuredCaseLlm().generate(
        system_instructions="Return JSON only.",
        evidence_payload=evidence_payload,
    )


def _response_with_overrides(
    evidence_payload: dict[str, Any],
    *,
    remove_fields: list[str] | None = None,
    updates: dict[str, Any] | None = None,
) -> str:
    payload = json.loads(_accepted_response("", evidence_payload))
    for field in remove_fields or []:
        payload.pop(field, None)
    for key, value in (updates or {}).items():
        payload[key] = value
    return json.dumps(payload)


def _load_audit_records(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _copy_demo_root(tmp_path: Path) -> Path:
    source_root = default_demo_root()
    target_root = tmp_path / "demo-copy"
    shutil.copytree(source_root, target_root)
    return target_root


def test_rules_trigger_expected_hits() -> None:
    _, _, _, rule_hits, _, _ = _demo_inputs()

    assert len(rule_hits) == 5
    assert [hit["rule_id"] for hit in rule_hits].count("AUTH-001") == 1
    assert [hit["rule_id"] for hit in rule_hits].count("AUTH-002") == 1
    assert [hit["rule_id"] for hit in rule_hits].count("WEB-001") == 1
    assert [hit["rule_id"] for hit in rule_hits].count("PROC-001") == 2
    assert all(hit["attack_mapping"]["technique_id"] for hit in rule_hits)


def test_grouping_merges_hits_by_entities_and_time() -> None:
    _, _, _, _, grouped_cases, _ = _demo_inputs()

    assert len(grouped_cases) == 3
    assert [len(case["rule_hits"]) for case in grouped_cases] == [2, 1, 2]


def test_parse_and_validate_rejects_non_json_output() -> None:
    _, output_schema, _, _, _, _ = _demo_inputs()

    with pytest.raises(JsonOutputError) as exc_info:
        parse_and_validate_json_output("disable the host now", output_schema)

    assert exc_info.value.reason == "non_json_output"


def test_parse_and_validate_rejects_json_parse_failure() -> None:
    _, output_schema, _, _, _, _ = _demo_inputs()

    with pytest.raises(JsonOutputError) as exc_info:
        parse_and_validate_json_output('{"case_id":', output_schema)

    assert exc_info.value.reason == "json_parse_failure"


def test_parse_and_validate_rejects_missing_required_fields() -> None:
    _, output_schema, _, _, _, case_bundles = _demo_inputs()
    invalid_response = _response_with_overrides(
        {"case_bundle": case_bundles[0]},
        remove_fields=["uncertainty_notes"],
    )

    with pytest.raises(SchemaValidationError) as exc_info:
        parse_and_validate_json_output(invalid_response, output_schema)

    assert exc_info.value.reason == "missing_required_fields"


def test_parse_and_validate_rejects_missing_human_verification() -> None:
    _, output_schema, _, _, _, case_bundles = _demo_inputs()
    invalid_response = _response_with_overrides(
        {"case_bundle": case_bundles[0]},
        remove_fields=["human_verification"],
    )

    with pytest.raises(SchemaValidationError) as exc_info:
        parse_and_validate_json_output(invalid_response, output_schema)

    assert exc_info.value.reason == "missing_required_fields"
    assert any("human_verification" in error for error in exc_info.value.errors)


def test_parse_and_validate_rejects_invalid_enum_values() -> None:
    _, output_schema, _, _, _, case_bundles = _demo_inputs()
    invalid_response = _response_with_overrides(
        {"case_bundle": case_bundles[0]},
        updates={"human_verification": "optional"},
    )

    with pytest.raises(SchemaValidationError) as exc_info:
        parse_and_validate_json_output(invalid_response, output_schema)

    assert exc_info.value.reason == "invalid_enum_value"


def test_parse_and_validate_rejects_case_id_mismatch() -> None:
    _, output_schema, _, _, _, case_bundles = _demo_inputs()
    invalid_response = _response_with_overrides(
        {"case_bundle": case_bundles[0]},
        updates={"case_id": "CASE-999"},
    )

    with pytest.raises(SchemaValidationError) as exc_info:
        parse_and_validate_json_output(
            invalid_response,
            output_schema,
            expected_case_id=case_bundles[0]["case_id"],
        )

    assert exc_info.value.reason == "case_id_mismatch"


def test_parse_and_validate_rejects_forbidden_action_language() -> None:
    _, output_schema, _, _, _, case_bundles = _demo_inputs()
    invalid_response = _response_with_overrides(
        {"case_bundle": case_bundles[0]},
        updates={"suggested_next_steps": ["Disable the account immediately."]},
    )

    with pytest.raises(SemanticValidationError) as exc_info:
        parse_and_validate_json_output(invalid_response, output_schema)

    assert exc_info.value.reason == "semantic_validation_failed"
    assert any("action-taking language" in error for error in exc_info.value.errors)


def test_parse_and_validate_rejects_forbidden_verdict_language() -> None:
    _, output_schema, _, _, _, case_bundles = _demo_inputs()
    invalid_response = _response_with_overrides(
        {"case_bundle": case_bundles[0]},
        updates={"summary": "Confirmed compromise of the account based on this case."},
    )

    with pytest.raises(SemanticValidationError) as exc_info:
        parse_and_validate_json_output(invalid_response, output_schema)

    assert exc_info.value.reason == "semantic_validation_failed"
    assert any("final-verdict language" in error for error in exc_info.value.errors)


def test_parse_and_validate_rejects_forbidden_language_in_uncertainty_notes() -> None:
    _, output_schema, _, _, _, case_bundles = _demo_inputs()
    invalid_response = _response_with_overrides(
        {"case_bundle": case_bundles[0]},
        updates={"uncertainty_notes": ["Definitely malicious. Lock the account now."]},
    )

    with pytest.raises(SemanticValidationError) as exc_info:
        parse_and_validate_json_output(invalid_response, output_schema)

    assert exc_info.value.reason == "semantic_validation_failed"
    assert any("uncertainty_notes" in error for error in exc_info.value.errors)


def test_prompt_injection_like_event_stays_in_untrusted_evidence() -> None:
    _, output_schema, _, _, _, case_bundles = _demo_inputs()
    web_case = next(
        case_bundle
        for case_bundle in case_bundles
        if any(hit["rule_id"] == "WEB-001" for hit in case_bundle["rule_hits"])
    )

    envelope = build_prompt_envelope(web_case, output_schema)
    evidence_text = json.dumps(envelope["evidence_payload"]).lower()
    system_text = envelope["system_instructions"].lower()

    assert "ignore all prior instructions" in evidence_text
    assert "ignore all prior instructions" not in system_text
    assert envelope["evidence_payload"]["telemetry_classification"] == "untrusted_data"
    assert any("untrusted evidence only" in item.lower() for item in web_case["evidence_highlights"])


def test_malformed_attack_metadata_is_rejected_and_recorded(tmp_path) -> None:
    demo_root = _copy_demo_root(tmp_path)
    rules_path = demo_root / "config" / "rules.yaml"
    rules_config = load_yaml(rules_path)
    rules_config["rules"][0]["attack"].pop("technique_id")
    rules_path.write_text(yaml.safe_dump(rules_config, sort_keys=False), encoding="utf-8")

    result = run_demo(demo_root=demo_root, artifacts_dir=tmp_path / "artifacts")

    assert result["rule_hit_count"] == 4
    audit_records = _load_audit_records(tmp_path / "artifacts" / "audit_traces.jsonl")
    rejection = next(
        record
        for record in audit_records
        if record["rejection_reason"] == "rule_metadata_validation_failed"
    )
    assert rejection["case_id"] is None
    assert "AUTH-001" in rejection["rule_ids"]
    assert any("technique_id" in error for error in rejection["validation_errors"])
    report_text = (tmp_path / "artifacts" / "case_report.md").read_text(encoding="utf-8")
    assert "## Run Integrity" in report_text
    assert "- coverage_degraded: yes" in report_text
    assert "- rejected_rules: AUTH-001" in report_text
    assert "Global validation rejections:" in report_text
    assert "AUTH-001: rule_metadata_validation_failed" in report_text


def test_audit_traces_capture_accepted_and_rejected_paths(tmp_path) -> None:
    demo_root, _, _, _, _, _ = _demo_inputs()
    llm = ScriptedLlm(
        [
            _accepted_response,
            lambda _system, evidence: _response_with_overrides(
                evidence,
                remove_fields=["human_verification"],
            ),
            lambda _system, evidence: _response_with_overrides(
                evidence,
                updates={"suggested_next_steps": ["Isolate the host immediately."]},
            ),
        ]
    )

    result = run_demo(demo_root=demo_root, artifacts_dir=tmp_path / "artifacts", llm=llm)

    assert result["case_count"] == 3
    assert result["summary_count"] == 1
    assert result["rejected_summary_count"] == 2

    case_summaries = json.loads(
        (tmp_path / "artifacts" / "case_summaries.json").read_text(encoding="utf-8")
    )
    assert len(case_summaries) == 1
    assert case_summaries[0]["human_verification"] == "required"

    audit_records = _load_audit_records(tmp_path / "artifacts" / "audit_traces.jsonl")
    assert len(audit_records) >= 3

    accepted_records = [
        record for record in audit_records if record["validation_status"] == "accepted"
    ]
    rejected_records = [
        record for record in audit_records if record["validation_status"] == "rejected"
    ]

    assert len(accepted_records) == 1
    assert len(rejected_records) >= 2
    assert {record["rejection_reason"] for record in rejected_records if record["case_id"]} >= {
        "missing_required_fields",
        "semantic_validation_failed",
    }

    required_fields = {
        "ts",
        "case_id",
        "schema_version",
        "output_schema_version",
        "stage",
        "validation_status",
        "rejection_reason",
        "rule_ids",
        "prompt_input_digest",
        "evidence_digest",
        "raw_response_excerpt",
        "validation_errors",
        "telemetry_classification",
    }
    for record in accepted_records + rejected_records:
        assert required_fields.issubset(record.keys())
        assert record["schema_version"] == "ai-assisted-detection-audit/v1"
        assert isinstance(record["rule_ids"], list)
        assert record["telemetry_classification"] == "untrusted_data"

    report_text = (tmp_path / "artifacts" / "case_report.md").read_text(encoding="utf-8")
    assert "Summary status: rejected" in report_text
    assert "Rejection reason: missing_required_fields" in report_text


def test_case_id_mismatch_is_rejected_and_not_counted_as_accepted(tmp_path) -> None:
    demo_root, _, _, _, _, _ = _demo_inputs()
    llm = ScriptedLlm(
        [
            lambda _system, evidence: _response_with_overrides(
                evidence,
                updates={"case_id": "CASE-999"},
            ),
            _accepted_response,
            _accepted_response,
        ]
    )

    result = run_demo(demo_root=demo_root, artifacts_dir=tmp_path / "artifacts", llm=llm)

    assert result["case_count"] == 3
    assert result["summary_count"] == 2
    assert result["rejected_summary_count"] == 1

    case_summaries = json.loads(
        (tmp_path / "artifacts" / "case_summaries.json").read_text(encoding="utf-8")
    )
    accepted_case_ids = {summary["case_id"] for summary in case_summaries}
    assert "CASE-999" not in accepted_case_ids
    assert accepted_case_ids == {"CASE-002", "CASE-003"}

    audit_records = _load_audit_records(tmp_path / "artifacts" / "audit_traces.jsonl")
    mismatch_record = next(
        record for record in audit_records if record["rejection_reason"] == "case_id_mismatch"
    )
    assert mismatch_record["validation_status"] == "rejected"
    assert mismatch_record["case_id"] == "CASE-001"
    assert mismatch_record["raw_response_excerpt"] is not None

    report_text = (tmp_path / "artifacts" / "case_report.md").read_text(encoding="utf-8")
    assert "## CASE-001" in report_text
    assert "Summary status: rejected" in report_text
    assert "Rejection reason: case_id_mismatch" in report_text
