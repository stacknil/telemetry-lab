from __future__ import annotations

import json
from pathlib import Path

from telemetry_window_demo.rule_evaluation_and_dedup_demo import default_demo_root, run_demo
from telemetry_window_demo.rule_evaluation_and_dedup_demo.pipeline import (
    deduplicate_rule_hits,
    group_rule_hits_by_cooldown_key,
    load_json,
    normalize_rule_hits,
)


def _load_demo_hits() -> list[dict[str, object]]:
    demo_root = default_demo_root()
    return normalize_rule_hits(
        load_json(demo_root / "data" / "raw" / "sample_rule_hits.json")
    )


def _load_json_file(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _make_hit(hit_id: str, alert_time: str) -> dict[str, str]:
    minute = int(alert_time[14:16])
    second = int(alert_time[17:19])
    total_seconds = minute * 60 + second - 60
    start_minute = total_seconds // 60
    start_second = total_seconds % 60
    return {
        "hit_id": hit_id,
        "rule_name": "login_fail_burst",
        "severity": "high",
        "alert_time": alert_time,
        "window_start": f"2026-03-18T10:{start_minute:02d}:{start_second:02d}Z",
        "window_end": alert_time,
        "entity": "account:carol",
        "message": "login_fail_count reached 8, threshold is 8",
    }


def test_group_rule_hits_by_rule_and_resolved_scope() -> None:
    grouped = group_rule_hits_by_cooldown_key(_load_demo_hits())
    counts = {group["cooldown_key"]: group["raw_hit_count"] for group in grouped}

    assert counts == {
        "login_fail_burst|entity=account:alice": 3,
        "login_fail_burst|entity=account:bob": 2,
        "high_error_rate|source=api-01": 3,
        "rare_event_repeat_malware_alert|unscoped": 2,
    }


def test_deduplicate_rule_hits_respects_cooldown_boundary() -> None:
    hits = normalize_rule_hits(
        [
            _make_hit("BOUNDARY-001", "2026-03-18T10:01:00Z"),
            _make_hit("BOUNDARY-002", "2026-03-18T10:03:59Z"),
            _make_hit("BOUNDARY-003", "2026-03-18T10:04:00Z"),
        ]
    )

    retained_hits, explanations = deduplicate_rule_hits(hits, cooldown_seconds=180)

    assert [hit["hit_id"] for hit in retained_hits] == ["BOUNDARY-001", "BOUNDARY-003"]
    assert [item["status"] for item in explanations] == ["retained", "suppressed", "retained"]
    suppressed = next(item for item in explanations if item["status"] == "suppressed")
    assert suppressed["hit_id"] == "BOUNDARY-002"
    assert suppressed["seconds_since_last_retained"] == 179


def test_deduplicate_rule_hits_records_suppression_reasons() -> None:
    retained_hits, explanations = deduplicate_rule_hits(_load_demo_hits(), cooldown_seconds=180)

    suppressed = next(item for item in explanations if item["hit_id"] == "RH-002")
    assert suppressed["status"] == "suppressed"
    assert suppressed["suppressed_by_hit_id"] == "RH-001"
    assert suppressed["seconds_since_last_retained"] == 40
    assert "40 seconds later" in suppressed["reason"]
    assert "180 second cooldown" in suppressed["reason"]

    first_retained = next(item for item in retained_hits if item["hit_id"] == "RH-001")
    assert first_retained["suppressed_hit_ids"] == ["RH-002"]


def test_run_demo_is_deterministic_and_matches_committed_artifacts(tmp_path) -> None:
    demo_root = default_demo_root()
    first_dir = tmp_path / "run-one"
    second_dir = tmp_path / "run-two"

    first_result = run_demo(demo_root=demo_root, artifacts_dir=first_dir)
    second_result = run_demo(demo_root=demo_root, artifacts_dir=second_dir)

    assert first_result["raw_hit_count"] == 10
    assert first_result["retained_alert_count"] == 6
    assert first_result["suppressed_hit_count"] == 4
    assert first_result["group_count"] == 4
    assert second_result["retained_alert_count"] == first_result["retained_alert_count"]

    for name in (
        "rule_hits_before_dedup.json",
        "rule_hits_after_dedup.json",
        "dedup_explanations.json",
    ):
        expected = _load_json_file(demo_root / "artifacts" / name)
        first = _load_json_file(first_dir / name)
        second = _load_json_file(second_dir / name)
        assert first == expected
        assert second == expected

    expected_report = (demo_root / "artifacts" / "dedup_report.md").read_text(encoding="utf-8")
    assert (first_dir / "dedup_report.md").read_text(encoding="utf-8") == expected_report
    assert (second_dir / "dedup_report.md").read_text(encoding="utf-8") == expected_report
