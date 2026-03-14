from __future__ import annotations

import pandas as pd

from telemetry_window_demo.preprocess import normalize_events
from telemetry_window_demo.windowing import build_windows


def test_build_windows_creates_expected_ranges() -> None:
    events = pd.DataFrame(
        [
            {
                "timestamp": "2026-03-10T10:00:00Z",
                "event_type": "login_success",
                "source": "user_a",
                "target": "auth",
                "status": "ok",
            },
            {
                "timestamp": "2026-03-10T10:00:20Z",
                "event_type": "login_fail",
                "source": "user_b",
                "target": "auth",
                "status": "fail",
            },
            {
                "timestamp": "2026-03-10T10:01:05Z",
                "event_type": "login_fail",
                "source": "user_c",
                "target": "auth",
                "status": "fail",
            },
        ]
    )
    normalized = normalize_events(events)

    windows = build_windows(
        normalized,
        timestamp_col="timestamp",
        window_size_seconds=60,
        step_size_seconds=30,
    )

    assert len(windows) == 3
    assert windows[0].start.isoformat() == "2026-03-10T10:00:00+00:00"
    assert windows[0].end.isoformat() == "2026-03-10T10:01:00+00:00"
    assert windows[0].start_index == 0
    assert windows[0].end_index == 2
    assert windows[-1].start.isoformat() == "2026-03-10T10:01:00+00:00"


def test_build_windows_handles_microsecond_backed_timestamps() -> None:
    events = pd.DataFrame(
        [
            {
                "timestamp": "2026-03-10T10:00:01Z",
                "event_type": "login_success",
                "source": "user_a",
                "target": "auth",
                "status": "ok",
            },
            {
                "timestamp": "2026-03-10T10:00:20Z",
                "event_type": "login_fail",
                "source": "user_b",
                "target": "auth",
                "status": "fail",
            },
            {
                "timestamp": "2026-03-10T10:00:50Z",
                "event_type": "login_fail",
                "source": "user_c",
                "target": "auth",
                "status": "fail",
            },
        ]
    )
    normalized = normalize_events(events)
    if hasattr(normalized["timestamp"].dt, "as_unit"):
        normalized["timestamp"] = normalized["timestamp"].dt.as_unit("us")

    windows = build_windows(
        normalized,
        timestamp_col="timestamp",
        window_size_seconds=60,
        step_size_seconds=10,
    )

    assert windows[0].start_index == 0
    assert windows[0].end_index == 3
    assert windows[1].start_index == 1
    assert windows[1].end_index == 3
