from __future__ import annotations

from collections import Counter

import pandas as pd
import pytest

from telemetry_window_demo.features import compute_window_features
from telemetry_window_demo.preprocess import normalize_events
from telemetry_window_demo.rules import ALERT_COLUMNS, apply_rules
from telemetry_window_demo.windowing import build_windows


def _event(
    timestamp: str,
    event_type: str = "login_success",
    source: str = "user_a",
    target: str = "auth",
    status: str = "ok",
    severity: str = "low",
) -> dict[str, str]:
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "source": source,
        "target": target,
        "status": status,
        "severity": severity,
    }


def test_empty_input_produces_no_windows_features_or_alerts() -> None:
    events = pd.DataFrame(columns=["timestamp", "event_type", "source", "target", "status"])

    normalized = normalize_events(events)
    windows = build_windows(
        normalized,
        timestamp_col="timestamp",
        window_size_seconds=60,
        step_size_seconds=10,
    )
    features = compute_window_features(
        normalized,
        windows,
        count_event_types=["login_fail"],
    )
    alerts = apply_rules(features, {"high_error_rate": {"threshold": 0.30}})

    assert normalized.empty
    assert windows == []
    assert features.empty
    assert alerts.empty
    assert tuple(alerts.columns) == ALERT_COLUMNS


def test_single_event_input_creates_one_window_with_one_counted_event() -> None:
    events = pd.DataFrame(
        [
            _event(
                "2026-03-10T10:00:07Z",
                event_type="login_fail",
                source="user_b",
                status="fail",
            )
        ]
    )

    normalized = normalize_events(events)
    windows = build_windows(
        normalized,
        timestamp_col="timestamp",
        window_size_seconds=60,
        step_size_seconds=10,
    )
    features = compute_window_features(
        normalized,
        windows,
        count_event_types=["login_fail"],
    )

    assert len(windows) == 1
    assert features.loc[0, "window_start"] == pd.Timestamp("2026-03-10T10:00:00Z")
    assert features.loc[0, "window_end"] == pd.Timestamp("2026-03-10T10:01:00Z")
    assert features.loc[0, "event_count"] == 1
    assert features.loc[0, "error_count"] == 1
    assert features.loc[0, "login_fail_count"] == 1


def test_duplicate_timestamps_are_counted_in_the_same_window() -> None:
    events = pd.DataFrame(
        [
            _event("2026-03-10T10:00:00Z", event_type="login_fail", source="user_a", status="fail"),
            _event("2026-03-10T10:00:00Z", event_type="login_fail", source="user_b", status="fail"),
            _event("2026-03-10T10:00:05Z", event_type="login_success", source="user_c"),
        ]
    )

    normalized = normalize_events(events)
    windows = build_windows(
        normalized,
        timestamp_col="timestamp",
        window_size_seconds=10,
        step_size_seconds=10,
    )
    features = compute_window_features(
        normalized,
        windows,
        count_event_types=["login_fail", "login_success"],
    )

    assert len(features) == 1
    assert features.loc[0, "event_count"] == 3
    assert features.loc[0, "login_fail_count"] == 2
    assert features.loc[0, "login_success_count"] == 1


def test_events_on_window_boundaries_follow_left_closed_right_open_windows() -> None:
    events = pd.DataFrame(
        [
            _event("2026-03-10T10:00:00Z", event_type="login_success", source="user_a"),
            _event("2026-03-10T10:00:10Z", event_type="login_fail", source="user_b", status="fail"),
        ]
    )

    normalized = normalize_events(events)
    windows = build_windows(
        normalized,
        timestamp_col="timestamp",
        window_size_seconds=10,
        step_size_seconds=10,
    )
    features = compute_window_features(
        normalized,
        windows,
        count_event_types=["login_fail", "login_success"],
    )

    assert len(features) == 2
    assert list(features["event_count"]) == [1, 1]
    assert list(features["login_success_count"]) == [1, 0]
    assert list(features["login_fail_count"]) == [0, 1]


def test_small_window_and_step_sizes_keep_overlapping_counts_explicit() -> None:
    events = pd.DataFrame(
        [
            _event("2026-03-10T10:00:00Z", event_type="login_fail", source="user_a", status="fail"),
            _event("2026-03-10T10:00:01Z", event_type="login_fail", source="user_b", status="fail"),
            _event("2026-03-10T10:00:02Z", event_type="login_success", source="user_c"),
        ]
    )

    normalized = normalize_events(events)
    windows = build_windows(
        normalized,
        timestamp_col="timestamp",
        window_size_seconds=2,
        step_size_seconds=1,
    )
    features = compute_window_features(
        normalized,
        windows,
        count_event_types=["login_fail", "login_success"],
    )

    assert len(windows) == 3
    assert list(features["event_count"]) == [2, 2, 1]
    assert list(features["login_fail_count"]) == [2, 1, 0]
    assert list(features["login_success_count"]) == [0, 1, 1]


def test_normalize_events_sorts_out_of_order_timestamps_before_windowing() -> None:
    events = pd.DataFrame(
        [
            _event("2026-03-10T10:00:10Z", event_type="latest", source="user_c"),
            _event("2026-03-10T10:00:00Z", event_type="earliest", source="user_a"),
            _event("2026-03-10T10:00:05Z", event_type="middle", source="user_b"),
        ]
    )

    normalized = normalize_events(events)
    windows = build_windows(
        normalized,
        timestamp_col="timestamp",
        window_size_seconds=10,
        step_size_seconds=10,
    )
    features = compute_window_features(
        normalized,
        windows,
        count_event_types=["earliest", "middle", "latest"],
    )

    assert list(normalized["event_type"]) == ["earliest", "middle", "latest"]
    assert list(features["event_count"]) == [2, 1]
    assert list(features["earliest_count"]) == [1, 0]
    assert list(features["middle_count"]) == [1, 0]
    assert list(features["latest_count"]) == [0, 1]


def test_mixed_timezone_offsets_normalize_to_correct_order_and_window_counts() -> None:
    events = pd.DataFrame(
        [
            _event("2026-03-10T10:00:00Z", event_type="z_event", source="user_z", target="svc"),
            _event(
                "2026-03-10T05:00:05-05:00",
                event_type="offset_event",
                source="user_offset",
                target="svc",
            ),
            _event("2026-03-10T10:00:10Z", event_type="later_event", source="user_later", target="svc"),
        ]
    )

    normalized = normalize_events(events)
    windows = build_windows(
        normalized,
        timestamp_col="timestamp",
        window_size_seconds=10,
        step_size_seconds=5,
    )
    features = compute_window_features(
        normalized,
        windows,
        count_event_types=["z_event", "offset_event", "later_event"],
    )

    assert list(normalized["timestamp"]) == [
        pd.Timestamp("2026-03-10T10:00:00Z"),
        pd.Timestamp("2026-03-10T10:00:05Z"),
        pd.Timestamp("2026-03-10T10:00:10Z"),
    ]
    assert list(normalized["event_type"]) == ["z_event", "offset_event", "later_event"]
    assert list(features["event_count"]) == [2, 2, 1]
    assert list(features["z_event_count"]) == [1, 0, 0]
    assert list(features["offset_event_count"]) == [1, 1, 0]
    assert list(features["later_event_count"]) == [0, 1, 1]


def test_naive_timestamps_normalize_to_utc_and_window_consistently() -> None:
    events = pd.DataFrame(
        [
            _event(
                "2026-03-10 10:00:00",
                event_type="naive_event",
                source="user_naive",
                target="svc",
            ),
            _event(
                "2026-03-10 10:00:05",
                event_type="second_naive_event",
                source="user_second",
                target="svc",
            ),
            _event(
                "2026-03-10 10:00:10",
                event_type="later_event",
                source="user_later",
                target="svc",
            ),
        ]
    )

    normalized = normalize_events(events)
    windows = build_windows(
        normalized,
        timestamp_col="timestamp",
        window_size_seconds=10,
        step_size_seconds=5,
    )
    features = compute_window_features(
        normalized,
        windows,
        count_event_types=["naive_event", "second_naive_event", "later_event"],
    )

    assert list(normalized["timestamp"]) == [
        pd.Timestamp("2026-03-10T10:00:00Z"),
        pd.Timestamp("2026-03-10T10:00:05Z"),
        pd.Timestamp("2026-03-10T10:00:10Z"),
    ]
    assert list(normalized["event_type"]) == [
        "naive_event",
        "second_naive_event",
        "later_event",
    ]
    assert list(features["event_count"]) == [2, 2, 1]
    assert list(features["naive_event_count"]) == [1, 0, 0]
    assert list(features["second_naive_event_count"]) == [1, 1, 0]
    assert list(features["later_event_count"]) == [0, 1, 1]


def test_normalize_events_raises_on_invalid_timestamp() -> None:
    events = pd.DataFrame(
        [
            _event("2026-03-10T10:00:00Z", event_type="ok_event", source="user_a", target="svc"),
            _event(
                "not-a-real-timestamp",
                event_type="bad_event",
                source="user_b",
                target="svc",
                status="fail",
            ),
        ]
    )

    with pytest.raises(ValueError, match="invalid timestamps"):
        normalize_events(events)


def test_threshold_equality_is_explicit_for_strict_vs_inclusive_rules() -> None:
    features = pd.DataFrame(
        [
            {
                "window_start": pd.Timestamp("2026-03-10T10:00:00Z"),
                "window_end": pd.Timestamp("2026-03-10T10:01:00Z"),
                "event_count": 10,
                "error_count": 3,
                "error_rate": 0.30,
                "unique_sources": 8,
                "unique_targets": 2,
                "high_severity_count": 2,
                "login_fail_count": 7,
                "malware_alert_count": 1,
            },
            {
                "window_start": pd.Timestamp("2026-03-10T10:01:00Z"),
                "window_end": pd.Timestamp("2026-03-10T10:02:00Z"),
                "event_count": 10,
                "error_count": 3,
                "error_rate": 0.30,
                "unique_sources": 12,
                "unique_targets": 2,
                "high_severity_count": 3,
                "login_fail_count": 8,
                "malware_alert_count": 2,
            },
        ]
    )
    config = {
        "high_error_rate": {"threshold": 0.30, "severity": "medium"},
        "login_fail_burst": {"threshold": 8, "severity": "high"},
        "high_severity_spike": {"threshold": 3, "severity": "high"},
        "persistent_high_error": {
            "threshold": 0.30,
            "consecutive_windows": 2,
            "severity": "medium",
        },
        "source_spread_spike": {
            "absolute_threshold": 12,
            "multiplier": 1.5,
            "severity": "medium",
        },
        "rare_event_repeat": {
            "threshold": 2,
            "event_types": ["malware_alert"],
            "severity": "high",
        },
    }

    alerts = apply_rules(features, config)

    rule_counts = Counter(alerts["rule_name"])
    assert rule_counts == Counter(
        {
            "high_severity_spike": 1,
            "login_fail_burst": 1,
            "rare_event_repeat_malware_alert": 1,
            "source_spread_spike": 1,
        }
    )
