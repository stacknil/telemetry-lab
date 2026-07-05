from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest
import yaml

from telemetry_lab.cloud_iam_change_investigation_demo import (
    default_demo_root,
    run_demo,
)
from telemetry_lab.cloud_iam_change_investigation_demo.pipeline import (
    CLOUDTRAIL_REQUIRED_FIELDS,
    evaluate_cloud_iam_signals,
    format_timestamp,
    load_jsonl,
    load_yaml,
    normalize_cloudtrail_events,
    opens_ingress_to_world,
    validate_demo_config,
)


def _demo_inputs():
    demo_root = default_demo_root()
    config = validate_demo_config(load_yaml(demo_root / "config" / "investigation.yaml"))
    raw_events = load_jsonl(
        demo_root / "data" / "raw" / "synthetic_cloudtrail_like_events.jsonl"
    )
    normalized_events = normalize_cloudtrail_events(raw_events)
    signals = evaluate_cloud_iam_signals(normalized_events, config)
    return demo_root, config, raw_events, normalized_events, signals


def _load_json_file(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _copy_demo_root(tmp_path: Path) -> Path:
    source_root = default_demo_root()
    target_root = tmp_path / "demo-copy"
    shutil.copytree(source_root, target_root)
    return target_root


def test_raw_events_follow_cloudtrail_like_skeleton() -> None:
    _, _, raw_events, _, _ = _demo_inputs()

    assert len(raw_events) == 14
    for event in raw_events:
        assert set(CLOUDTRAIL_REQUIRED_FIELDS).issubset(event)


def test_normalize_cloudtrail_events_is_sorted_and_derives_actor() -> None:
    _, _, _, normalized_events, _ = _demo_inputs()

    assert [event["eventID"] for event in normalized_events[:3]] == [
        "evt-cti-001",
        "evt-cti-002",
        "evt-cti-003",
    ]
    assert normalized_events[0]["actor"] == "USER_A"
    assert normalized_events[0]["outcome"] == "failure"
    assert normalized_events[4]["eventName"] == "CreateAccessKey"
    assert normalized_events[4]["outcome"] == "success"


def test_normalize_cloudtrail_events_uses_event_time_not_observed_time_for_ordering() -> None:
    _, _, raw_events, _, _ = _demo_inputs()
    event_a = {
        **raw_events[0],
        "eventID": "evt-time-a",
        "eventTime": "2026-04-07T10:05:00Z",
        "observedTime": "2026-04-07T10:00:00Z",
    }
    event_b = {
        **raw_events[1],
        "eventID": "evt-time-b",
        "eventTime": "2026-04-07T10:01:00Z",
        "observedTime": "2026-04-07T10:30:00Z",
    }

    normalized = normalize_cloudtrail_events([event_a, event_b])

    assert [event["eventID"] for event in normalized] == ["evt-time-b", "evt-time-a"]
    assert format_timestamp(normalized[0]["event_time"]) == "2026-04-07T10:01:00Z"
    assert format_timestamp(normalized[0]["observed_time"]) == "2026-04-07T10:30:00Z"


def test_evaluate_cloud_iam_signals_flags_expected_rules() -> None:
    _, _, _, _, signals = _demo_inputs()

    assert [signal["rule_id"] for signal in signals] == [
        "failed_console_login_burst",
        "new_access_key_creation_after_failed_logins",
        "policy_attachment_after_unusual_source_ip",
        "cloudtrail_logging_disabled_near_iam_change",
        "security_group_ingress_opened_after_identity_change",
    ]
    assert [signal["severity"] for signal in signals] == [
        "medium",
        "high",
        "high",
        "critical",
        "high",
    ]


def test_rule_evidence_stays_bounded_to_configured_windows() -> None:
    _, _, _, _, signals = _demo_inputs()

    access_key_signal = next(
        signal
        for signal in signals
        if signal["rule_id"] == "new_access_key_creation_after_failed_logins"
    )
    logging_signal = next(
        signal
        for signal in signals
        if signal["rule_id"] == "cloudtrail_logging_disabled_near_iam_change"
    )
    ingress_signal = next(
        signal
        for signal in signals
        if signal["rule_id"] == "security_group_ingress_opened_after_identity_change"
    )

    assert access_key_signal["evidence_event_ids"] == [
        "evt-cti-001",
        "evt-cti-002",
        "evt-cti-003",
        "evt-cti-005",
    ]
    assert logging_signal["evidence_event_ids"] == [
        "evt-cti-005",
        "evt-cti-006",
        "evt-cti-007",
    ]
    assert "evt-cti-014" not in logging_signal["evidence_event_ids"]
    assert ingress_signal["evidence_event_ids"] == [
        "evt-cti-005",
        "evt-cti-006",
        "evt-cti-008",
    ]


def test_opens_ingress_to_world_only_matches_world_routable_ranges() -> None:
    _, _, _, normalized_events, _ = _demo_inputs()
    open_ingress = next(event for event in normalized_events if event["eventID"] == "evt-cti-008")
    internal_ingress = next(
        event for event in normalized_events if event["eventID"] == "evt-cti-012"
    )

    assert opens_ingress_to_world(open_ingress) is True
    assert opens_ingress_to_world(internal_ingress) is False


def test_attack_mapping_set_stays_small_and_expected() -> None:
    _, config, _, _, signals = _demo_inputs()

    assert set(config["attack_mappings"]) == {
        "T1078.004",
        "T1110.003",
        "T1098.001",
        "T1685.002",
        "T1578",
    }
    assert len(config["attack_mappings"]) == 5
    assert all(signal["attack_mappings"] for signal in signals)


def test_sample_data_uses_synthetic_identifiers_only() -> None:
    demo_root, _, _, _, _ = _demo_inputs()
    raw_text = (
        demo_root / "data" / "raw" / "synthetic_cloudtrail_like_events.jsonl"
    ).read_text(encoding="utf-8")

    assert "SYNTHETIC_ACCOUNT" in raw_text
    assert "AKIA" not in raw_text
    assert re.search(r"\b\d{12}\b", raw_text) is None


def test_validate_demo_config_rejects_more_than_five_attack_mappings() -> None:
    _, config, _, _, _ = _demo_inputs()
    config["attack_mappings"]["T0000"] = {
        "name": "extra mapping",
        "tactic": "test",
        "reference": "https://example.com",
    }

    with pytest.raises(ValueError, match="at most 5"):
        validate_demo_config(config)


@pytest.mark.parametrize(
    ("mutator", "expected_error"),
    [
        (
            lambda config: config.update({"unused": True}),
            "Unknown config field",
        ),
        (
            lambda config: config["rules"]["failed_console_login_burst"].update(
                {"typo_threshold": 3}
            ),
            "rules.failed_console_login_burst",
        ),
        (
            lambda config: config["attack_mappings"]["T1078.004"].update(
                {"platform": "cloud"}
            ),
            "attack_mappings.T1078.004",
        ),
    ],
)
def test_validate_demo_config_rejects_unknown_fields(mutator, expected_error) -> None:
    _, config, _, _, _ = _demo_inputs()
    mutator(config)

    with pytest.raises(ValueError, match=expected_error):
        validate_demo_config(config)


def test_normalize_cloudtrail_events_reports_missing_required_field() -> None:
    _, _, raw_events, _, _ = _demo_inputs()
    broken_event = dict(raw_events[0])
    broken_event.pop("sourceIPAddress")

    with pytest.raises(ValueError, match="sourceIPAddress"):
        normalize_cloudtrail_events([broken_event])


def test_run_demo_is_deterministic_and_matches_committed_artifacts(tmp_path) -> None:
    demo_root, _, _, _, _ = _demo_inputs()
    first_dir = tmp_path / "run-one"
    second_dir = tmp_path / "run-two"

    first_result = run_demo(demo_root=demo_root, artifacts_dir=first_dir)
    second_result = run_demo(demo_root=demo_root, artifacts_dir=second_dir)

    assert first_result["raw_event_count"] == 14
    assert first_result["rule_count"] == 5
    assert first_result["signal_count"] == 5
    assert second_result["signal_count"] == first_result["signal_count"]
    generated_summary = _load_json_file(first_dir / "investigation_summary.json")
    assert generated_summary["time_model"] == {
        "event_time_source": "eventTime",
        "observed_time_source": "observedTime when present",
        "detection_ordering": "event_time",
        "observed_time_event_count": 0,
    }

    for name in (
        "normalized_cloudtrail_events.json",
        "investigation_signals.json",
        "investigation_summary.json",
    ):
        expected = _load_json_file(demo_root / "artifacts" / name)
        first = _load_json_file(first_dir / name)
        second = _load_json_file(second_dir / name)
        assert first == expected
        assert second == expected

    expected_report = (demo_root / "artifacts" / "investigation_report.md").read_text(
        encoding="utf-8"
    )
    assert (first_dir / "investigation_report.md").read_text(encoding="utf-8") == expected_report
    assert (second_dir / "investigation_report.md").read_text(encoding="utf-8") == expected_report


def test_run_demo_rejects_file_artifacts_dir(tmp_path) -> None:
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.write_text("not a directory\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Output directory path is not a directory"):
        run_demo(demo_root=default_demo_root(), artifacts_dir=artifacts_dir)


def test_run_demo_reports_config_errors_before_loading_inputs(tmp_path) -> None:
    demo_root = _copy_demo_root(tmp_path)
    config_path = demo_root / "config" / "investigation.yaml"
    config = load_yaml(config_path)
    config["rules"]["failed_console_login_burst"]["threshold"] = 0
    config_path.write_text(
        yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="failed_console_login_burst.threshold"):
        run_demo(demo_root=demo_root, artifacts_dir=tmp_path / "artifacts")
