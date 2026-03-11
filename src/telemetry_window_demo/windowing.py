from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class WindowSlice:
    start: pd.Timestamp
    end: pd.Timestamp
    start_index: int
    end_index: int


def build_windows(
    events: pd.DataFrame,
    timestamp_col: str,
    window_size_seconds: int,
    step_size_seconds: int,
) -> list[WindowSlice]:
    if window_size_seconds <= 0 or step_size_seconds <= 0:
        raise ValueError("Window size and step size must be positive integers.")
    if events.empty:
        return []

    timestamps = events[timestamp_col]
    start = timestamps.min().floor(f"{step_size_seconds}s")
    last_start = timestamps.max().floor(f"{step_size_seconds}s")
    window_delta = pd.Timedelta(seconds=window_size_seconds)
    step_delta = pd.Timedelta(seconds=step_size_seconds)
    timestamp_ns = timestamps.array.asi8

    windows: list[WindowSlice] = []
    current = start
    while current <= last_start:
        end = current + window_delta
        start_index = int(timestamp_ns.searchsorted(current.value, side="left"))
        end_index = int(timestamp_ns.searchsorted(end.value, side="left"))
        windows.append(
            WindowSlice(
                start=current,
                end=end,
                start_index=start_index,
                end_index=end_index,
            )
        )
        current += step_delta

    return windows

