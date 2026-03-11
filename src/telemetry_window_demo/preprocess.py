from __future__ import annotations

import pandas as pd

from .schema import (
    DEFAULT_ERROR_STATUSES,
    DEFAULT_HIGH_SEVERITY_LEVELS,
    ensure_optional_columns,
)


def normalize_events(
    events: pd.DataFrame,
    timestamp_col: str = "timestamp",
    error_statuses: list[str] | tuple[str, ...] | None = None,
    high_severity_levels: list[str] | tuple[str, ...] | None = None,
) -> pd.DataFrame:
    normalized = ensure_optional_columns(events)
    normalized = normalized.copy()

    normalized[timestamp_col] = pd.to_datetime(
        normalized[timestamp_col],
        utc=True,
        errors="coerce",
    )
    invalid_rows = normalized[normalized[timestamp_col].isna()]
    if not invalid_rows.empty:
        raise ValueError(f"Found {len(invalid_rows)} rows with invalid timestamps.")

    normalized["event_type"] = normalized["event_type"].astype(str).str.strip()
    normalized["source"] = normalized["source"].astype(str).str.strip()
    normalized["target"] = normalized["target"].astype(str).str.strip()
    normalized["status"] = (
        normalized["status"].fillna("unknown").astype(str).str.strip().str.lower()
    )
    normalized["severity"] = (
        normalized["severity"].fillna("unknown").astype(str).str.strip().str.lower()
    )

    error_values = {value.lower() for value in error_statuses or DEFAULT_ERROR_STATUSES}
    severity_values = {
        value.lower() for value in high_severity_levels or DEFAULT_HIGH_SEVERITY_LEVELS
    }

    normalized["is_error"] = normalized["status"].isin(error_values)
    normalized["is_high_severity"] = normalized["severity"].isin(severity_values)

    normalized = normalized.sort_values(timestamp_col).reset_index(drop=True)
    return normalized

