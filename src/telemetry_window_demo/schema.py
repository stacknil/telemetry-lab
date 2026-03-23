from __future__ import annotations

import re

import pandas as pd

REQUIRED_COLUMNS = ("timestamp", "event_type", "source", "target", "status")
RECOMMENDED_COLUMNS = ("user", "host", "ip", "severity")
OPTIONAL_COLUMNS = RECOMMENDED_COLUMNS + ("metadata",)

DEFAULT_ERROR_STATUSES = ("fail", "blocked", "error")
DEFAULT_HIGH_SEVERITY_LEVELS = ("high", "critical")


def validate_event_frame(events: pd.DataFrame, source: str | None = None) -> None:
    location = f" in {source}" if source else ""
    missing = [column for column in REQUIRED_COLUMNS if column not in events.columns]
    if missing:
        raise ValueError(
            f"Missing required event fields{location}: {', '.join(missing)}"
        )

    missing_values: list[str] = []
    for column in REQUIRED_COLUMNS:
        values = events[column]
        missing_mask = values.isna()
        blank_mask = values.astype("string").str.strip().eq("").fillna(False)
        invalid_mask = missing_mask | blank_mask
        if invalid_mask.any():
            missing_values.append(f"{column} ({int(invalid_mask.sum())} row(s))")

    if missing_values:
        raise ValueError(
            f"Missing required event values{location}: {', '.join(missing_values)}"
        )


def ensure_optional_columns(events: pd.DataFrame) -> pd.DataFrame:
    normalized = events.copy()
    for column in OPTIONAL_COLUMNS:
        if column not in normalized.columns:
            normalized[column] = pd.NA
    return normalized


def event_count_column(event_type: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "_", event_type.strip().lower()).strip("_")
    return f"{token or 'unknown'}_count"

