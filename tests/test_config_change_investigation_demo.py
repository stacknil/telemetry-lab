from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from telemetry_window_demo.config_change_investigation_demo import default_demo_root, run_demo
from telemetry_window_demo.config_change_investigation_demo.pipeline import (
    build_investigations,
    evaluate_risky_config_changes,
    load_jsonl,
    load_yaml,
    normalize_config_changes,
    normalize_follow_on_events,
    normalize_policy_denials,
    parse_timestamp,
    validate_demo_config,
)


def _load_demo_inputs():
    demo_root = default_demo_root()
    config = load_yaml(demo_root / "config" / "investigation.yaml")
    config_changes = normalize_config_changes(
        load_jsonl(demo_root / "data" / "raw" / "config_changes.jsonl")
    )
    policy_denials = normalize_policy_denials(
        load_jsonl(demo_root / "data" / "raw" / "policy_denials.jsonl")
    )
    follow_on_events = normalize_follow_on_events(
        load_jsonl(demo_root / "data" / "raw" / "follow_on_events.jsonl")
    )
    return demo_root, config, config_changes, policy_denials, follow_on_events


def _load_json_file(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _copy_demo_root(tmp_path: Path) -> Path:
    source_root = default_demo_root()
    target_root = tmp_path / "demo-copy"
    shutil.copytree(source_root, target_root)
    return target_root


def test_normalize_config_changes_is_sorted_and_complete() -> None:
    _, _, config_changes, _, _ = _load_demo_inputs()

    assert [change["change_id"] for change in config_changes] == [
        "cfg-001",
        "cfg-002",
        "cfg-003",
        "cfg-004",
    ]
    assert config_changes[0]["target_system"] == "identity-proxy"
    assert config_changes[1]["config_key"] == "public_bind_cidr"


def test_evaluate_risky_config_changes_flags_expected_changes() -> None:
    _, config, config_changes, _, _ = _load_demo_inputs()
    hits = evaluate_risky_config_changes(config_changes, config["rules"])

    assert [hit["change_event"]["change_id"] for hit in hits] == [
        "cfg-001",
        "cfg-002",
        "cfg-004",
    ]
    assert [hit["severity"] for hit in hits] == ["critical", "high", "high"]


def test_parse_timestamp_treats_naive_values_as_utc() -> None:
    assert parse_timestamp("2026-03-20T09:15:00").isoformat() == (
        "2026-03-20T09:15:00+00:00"
    )


def test_build_investigations_uses_bounded_system_and_time_correlation() -> None:
    _, config, config_changes, policy_denials, follow_on_events = _load_demo_inputs()
    hits = evaluate_risky_config_changes(config_changes, config["rules"])
    investigations = build_investigations(
        hits,
        policy_denials,
        follow_on_events,
        correlation_minutes=int(config["correlation_minutes"]),
    )

    identity = next(item for item in investigations if item["investigation_id"] == "CCI-001")
    payments = next(item for item in investigations if item["investigation_id"] == "CCI-002")
    vault = next(item for item in investigations if item["investigation_id"] == "CCI-003")

    assert identity["evidence_counts"] == {"policy_denials": 2, "follow_on_events": 2}
    assert payments["evidence_counts"] == {"policy_denials": 1, "follow_on_events": 2}
    assert vault["evidence_counts"] == {"policy_denials": 0, "follow_on_events": 0}

    assert all(
        denial["target_system"] == "payments-api"
        for denial in payments["attached_policy_denials"]
    )
    assert all(
        event["event_id"] != "fo-005" for event in vault["attached_follow_on_events"]
    )


def test_build_investigations_includes_evidence_on_window_end_only() -> None:
    change_time = parse_timestamp("2026-03-20T09:00:00Z")
    rule_hits = [
        {
            "investigation_id": "CCI-999",
            "severity": "high",
            "rule_id": "cfg_test",
            "reason": "test rule",
            "change_event": {
                "change_id": "cfg-test",
                "timestamp": change_time,
                "actor": "operator",
                "target_system": "identity-proxy",
                "config_key": "test_key",
                "old_value": "safe",
                "new_value": "risky",
                "change_result": "success",
            },
        }
    ]
    policy_denials = [
        {
            "denial_id": "before",
            "timestamp": parse_timestamp("2026-03-20T08:59:59Z"),
            "actor": "operator",
            "target_system": "identity-proxy",
            "policy_name": "before",
            "decision": "deny",
            "reason": "too early",
        },
        {
            "denial_id": "on-end",
            "timestamp": parse_timestamp("2026-03-20T09:15:00Z"),
            "actor": "operator",
            "target_system": "identity-proxy",
            "policy_name": "boundary",
            "decision": "deny",
            "reason": "inside boundary",
        },
        {
            "denial_id": "after",
            "timestamp": parse_timestamp("2026-03-20T09:15:01Z"),
            "actor": "operator",
            "target_system": "identity-proxy",
            "policy_name": "after",
            "decision": "deny",
            "reason": "too late",
        },
    ]

    investigations = build_investigations(
        rule_hits,
        policy_denials,
        follow_on_events=[],
        correlation_minutes=15,
    )

    assert [item["denial_id"] for item in investigations[0]["attached_policy_denials"]] == [
        "on-end"
    ]


def test_build_investigations_rejects_non_positive_correlation_window() -> None:
    with pytest.raises(ValueError, match="correlation_minutes"):
        build_investigations([], [], [], correlation_minutes=0)


def test_validate_demo_config_reports_missing_input_path_key() -> None:
    _, config, _, _, _ = _load_demo_inputs()
    config["input_paths"].pop("policy_denials")

    with pytest.raises(ValueError, match="input_paths.policy_denials"):
        validate_demo_config(config)


def test_validate_demo_config_rejects_bad_correlation_window_type() -> None:
    _, config, _, _, _ = _load_demo_inputs()
    config["correlation_minutes"] = True

    with pytest.raises(ValueError, match="correlation_minutes"):
        validate_demo_config(config)


def test_validate_demo_config_rejects_missing_rules() -> None:
    _, config, _, _, _ = _load_demo_inputs()
    config["rules"] = []

    with pytest.raises(ValueError, match="rules"):
        validate_demo_config(config)


def test_run_demo_reports_config_errors_before_loading_inputs(tmp_path) -> None:
    demo_root = _copy_demo_root(tmp_path)
    config_path = demo_root / "config" / "investigation.yaml"
    config = load_yaml(config_path)
    config["input_paths"].pop("config_changes")
    config_path.write_text(
        yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="input_paths.config_changes"):
        run_demo(demo_root=demo_root, artifacts_dir=tmp_path / "artifacts")


def test_run_demo_rejects_file_artifacts_dir(tmp_path) -> None:
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.write_text("not a directory\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Output directory path is not a directory"):
        run_demo(demo_root=default_demo_root(), artifacts_dir=artifacts_dir)


def test_run_demo_is_deterministic_and_matches_committed_artifacts(tmp_path) -> None:
    demo_root, _, _, _, _ = _load_demo_inputs()
    first_dir = tmp_path / "run-one"
    second_dir = tmp_path / "run-two"

    first_result = run_demo(demo_root=demo_root, artifacts_dir=first_dir)
    second_result = run_demo(demo_root=demo_root, artifacts_dir=second_dir)

    assert first_result["change_event_count"] == 4
    assert first_result["risky_change_count"] == 3
    assert first_result["investigation_count"] == 3
    assert second_result["investigation_count"] == first_result["investigation_count"]

    for name in (
        "change_events_normalized.json",
        "investigation_hits.json",
        "investigation_summary.json",
    ):
        expected = _load_json_file(demo_root / "artifacts" / name)
        first = _load_json_file(first_dir / name)
        second = _load_json_file(second_dir / name)
        assert first == expected
        assert second == expected

    expected_report = (
        demo_root / "artifacts" / "investigation_report.md"
    ).read_text(encoding="utf-8")
    assert (first_dir / "investigation_report.md").read_text(encoding="utf-8") == expected_report
    assert (second_dir / "investigation_report.md").read_text(encoding="utf-8") == expected_report
