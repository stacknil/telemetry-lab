from __future__ import annotations

from datetime import UTC, datetime


def parse_utc_timestamp(raw_value: str) -> datetime:
    text = str(raw_value).strip()
    if not text:
        raise ValueError("Timestamp must be non-empty.")

    try:
        timestamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp: {raw_value!r}") from exc

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC)
