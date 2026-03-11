from __future__ import annotations

import re

import pandas as pd

REQUIRED_COLUMNS = ("timestamp", "event_type", "source", "target", "status")
RECOMMENDED_COLUMNS = ("user", "host", "ip", "severity")
OPTIONAL_COLUMNS = RECOMMENDED_COLUMNS + ("metadata",)

DEFAULT_ERROR_STATUSES = ("fail", "blocked", "error")
DEFAULT_HIGH_SEVERITY_LEVELS = ("high", "critical")


def validate_event_frame(events: pd.DataFrame) -> None:
    missing = [column for column in REQUIRED_COLUMNS if column not in events.columns]
    if missing:
        raise ValueError(f"Missing required event fields: {', '.join(missing)}")


def ensure_optional_columns(events: pd.DataFrame) -> pd.DataFrame:
    normalized = events.copy()
    for column in OPTIONAL_COLUMNS:
        if column not in normalized.columns:
            normalized[column] = pd.NA
    return normalized


def event_count_column(event_type: str) -> str:
    token = re.sub(r"[^a-z0-9]+", "_", event_type.strip().lower()).strip("_")
    return f"{token or 'unknown'}_count"

