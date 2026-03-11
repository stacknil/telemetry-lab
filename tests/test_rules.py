from __future__ import annotations

import pandas as pd

from telemetry_window_demo.rules import apply_rules


def test_apply_rules_triggers_expected_alerts() -> None:
    features = pd.DataFrame(
        [
            {
                "window_start": pd.Timestamp("2026-03-10T10:00:00Z"),
                "window_end": pd.Timestamp("2026-03-10T10:01:00Z"),
                "event_count": 12,
                "error_count": 5,
                "error_rate": 0.42,
                "unique_sources": 4,
                "unique_targets": 2,
                "high_severity_count": 1,
                "login_fail_count": 6,
                "malware_alert_count": 0,
            },
            {
                "window_start": pd.Timestamp("2026-03-10T10:00:10Z"),
                "window_end": pd.Timestamp("2026-03-10T10:01:10Z"),
                "event_count": 14,
                "error_count": 6,
                "error_rate": 0.43,
                "unique_sources": 11,
                "unique_targets": 3,
                "high_severity_count": 4,
                "login_fail_count": 8,
                "malware_alert_count": 0,
            },
            {
                "window_start": pd.Timestamp("2026-03-10T10:00:20Z"),
                "window_end": pd.Timestamp("2026-03-10T10:01:20Z"),
                "event_count": 10,
                "error_count": 5,
                "error_rate": 0.50,
                "unique_sources": 12,
                "unique_targets": 3,
                "high_severity_count": 4,
                "login_fail_count": 9,
                "malware_alert_count": 2,
            },
        ]
    )
    config = {
        "high_error_rate": {"threshold": 0.30, "severity": "medium"},
        "login_fail_burst": {"threshold": 8, "severity": "high"},
        "high_severity_spike": {"threshold": 3, "severity": "high"},
        "persistent_high_error": {
            "threshold": 0.25,
            "consecutive_windows": 2,
            "severity": "medium",
        },
        "source_spread_spike": {
            "absolute_threshold": 10,
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

    assert "high_error_rate" in set(alerts["rule_name"])
    assert "login_fail_burst" in set(alerts["rule_name"])
    assert "high_severity_spike" in set(alerts["rule_name"])
    assert "persistent_high_error" in set(alerts["rule_name"])
    assert "source_spread_spike" in set(alerts["rule_name"])
    assert "rare_event_repeat_malware_alert" in set(alerts["rule_name"])

