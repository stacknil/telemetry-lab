from __future__ import annotations

from datetime import timedelta

import pandas as pd
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from telemetry_lab.preprocess import normalize_events
from telemetry_lab.windowing import build_windows


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


def test_build_windows_rejects_unsorted_timestamps() -> None:
    events = pd.DataFrame(
        [
            {
                "timestamp": pd.Timestamp("2026-03-10T10:00:20Z"),
                "event_type": "login_fail",
                "source": "user_b",
                "target": "auth",
                "status": "fail",
            },
            {
                "timestamp": pd.Timestamp("2026-03-10T10:00:00Z"),
                "event_type": "login_success",
                "source": "user_a",
                "target": "auth",
                "status": "ok",
            },
        ]
    )

    with pytest.raises(ValueError, match="sorted by timestamp"):
        build_windows(
            events,
            timestamp_col="timestamp",
            window_size_seconds=60,
            step_size_seconds=10,
        )


@given(
    offsets=st.lists(
        st.integers(min_value=0, max_value=900),
        min_size=1,
        max_size=30,
        unique=True,
    ).map(sorted),
    window_size_seconds=st.integers(min_value=1, max_value=180),
    step_size_seconds=st.integers(min_value=1, max_value=120),
)
@settings(max_examples=80, deadline=None)
def test_build_windows_property_indexes_match_half_open_boundaries(
    offsets: list[int],
    window_size_seconds: int,
    step_size_seconds: int,
) -> None:
    base = pd.Timestamp("2026-03-10T10:00:00Z")
    timestamps = [base + timedelta(seconds=offset) for offset in offsets]
    events = pd.DataFrame({"timestamp": timestamps})

    windows = build_windows(
        events,
        timestamp_col="timestamp",
        window_size_seconds=window_size_seconds,
        step_size_seconds=step_size_seconds,
    )

    assert windows
    assert all(window.start < window.end for window in windows)
    assert [window.start for window in windows] == sorted(window.start for window in windows)

    for first, second in zip(windows, windows[1:]):
        assert second.start - first.start == pd.Timedelta(seconds=step_size_seconds)
        assert first.start_index <= second.start_index
        assert first.end_index <= second.end_index

    for window in windows:
        assert 0 <= window.start_index <= window.end_index <= len(timestamps)
        for index, timestamp in enumerate(timestamps):
            assert (window.start <= timestamp < window.end) == (
                window.start_index <= index < window.end_index
            )
