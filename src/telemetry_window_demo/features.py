from __future__ import annotations

from collections.abc import Iterable

import pandas as pd

from .schema import event_count_column
from .windowing import WindowSlice


def compute_window_features(
    events: pd.DataFrame,
    windows: Iterable[WindowSlice],
    count_event_types: list[str] | tuple[str, ...] | None = None,
) -> pd.DataFrame:
    event_types = list(count_event_types or [])
    rows: list[dict[str, object]] = []

    for window in windows:
        window_events = events.iloc[window.start_index : window.end_index]
        event_count = int(len(window_events))
        error_count = int(window_events["is_error"].sum()) if event_count else 0
        high_severity_count = (
            int(window_events["is_high_severity"].sum()) if event_count else 0
        )

        row: dict[str, object] = {
            "window_start": window.start,
            "window_end": window.end,
            "event_count": event_count,
            "error_count": error_count,
            "error_rate": (error_count / event_count) if event_count else 0.0,
            "unique_sources": int(window_events["source"].nunique(dropna=True))
            if event_count
            else 0,
            "unique_targets": int(window_events["target"].nunique(dropna=True))
            if event_count
            else 0,
            "high_severity_count": high_severity_count,
        }

        for event_type in event_types:
            row[event_count_column(event_type)] = int(
                (window_events["event_type"] == event_type).sum()
            )

        rows.append(row)

    return pd.DataFrame(rows)

