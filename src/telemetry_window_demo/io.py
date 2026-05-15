from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from .schema import validate_event_frame

FEATURE_TABLE_REQUIRED_COLUMNS = (
    "window_start",
    "window_end",
    "event_count",
    "error_rate",
)
FEATURE_TABLE_DATETIME_COLUMNS = ("window_start", "window_end")
ALERT_TABLE_REQUIRED_COLUMNS = (
    "alert_time",
    "window_start",
    "window_end",
    "rule_name",
    "severity",
)
ALERT_TABLE_DATETIME_COLUMNS = ("alert_time", "window_start", "window_end")


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            config = yaml.safe_load(handle) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML config in {config_path}: {exc}") from exc
    if not isinstance(config, dict):
        raise ValueError("Configuration must deserialize to a mapping.")
    return config


def resolve_config_path(config_path: str | Path, value: str | Path) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    base_dir = Path(config_path).resolve().parent
    if base_dir.name == "configs":
        base_dir = base_dir.parent
    return (base_dir / candidate).resolve()


def load_events(path: str | Path) -> pd.DataFrame:
    input_path = Path(path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    suffix = input_path.suffix.lower()
    if suffix == ".jsonl":
        records = []
        with input_path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                raw = line.strip()
                if not raw:
                    continue
                try:
                    record = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSONL in {input_path} at line {line_number}: {exc.msg}"
                    ) from exc
                if not isinstance(record, dict):
                    raise ValueError(
                        f"Invalid JSONL in {input_path} at line {line_number}: expected an object record"
                    )
                records.append(record)
        events = pd.DataFrame.from_records(records)
    elif suffix == ".csv":
        try:
            events = pd.read_csv(input_path, keep_default_na=False)
        except (
            pd.errors.EmptyDataError,
            pd.errors.ParserError,
            UnicodeDecodeError,
        ) as exc:
            raise ValueError(f"Invalid CSV in {input_path}: {exc}") from exc
    else:
        raise ValueError("Unsupported input format. Use .jsonl or .csv.")

    validate_event_frame(events, source=str(input_path))
    return events


def load_feature_table(path: str | Path) -> pd.DataFrame:
    table_path = Path(path)
    frame = pd.read_csv(table_path)
    _require_columns(frame, FEATURE_TABLE_REQUIRED_COLUMNS, source=str(table_path))
    _parse_datetime_columns(
        frame,
        FEATURE_TABLE_DATETIME_COLUMNS,
        source=str(table_path),
    )
    return frame


def load_alert_table(path: str | Path) -> pd.DataFrame:
    table_path = Path(path)
    frame = pd.read_csv(table_path)
    _require_columns(frame, ALERT_TABLE_REQUIRED_COLUMNS, source=str(table_path))
    _parse_datetime_columns(
        frame,
        ALERT_TABLE_DATETIME_COLUMNS,
        source=str(table_path),
    )
    return frame


def _require_columns(
    frame: pd.DataFrame,
    required_columns: tuple[str, ...],
    *,
    source: str,
) -> None:
    missing_columns = [
        column for column in required_columns if column not in frame.columns
    ]
    if missing_columns:
        raise ValueError(
            f"Missing required columns in {source}: " + ", ".join(missing_columns)
        )


def _parse_datetime_columns(
    frame: pd.DataFrame,
    datetime_columns: tuple[str, ...],
    *,
    source: str,
) -> None:
    for column in datetime_columns:
        try:
            parsed = pd.to_datetime(frame[column], utc=True, errors="raise")
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Invalid datetime values in {source}: {column}"
            ) from exc
        if parsed.isna().any():
            raise ValueError(f"Missing datetime values in {source}: {column}")
        frame[column] = parsed


def write_table(frame: pd.DataFrame, path: str | Path) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    export = frame.copy()
    for column in export.columns:
        dtype = export[column].dtype
        if pd.api.types.is_datetime64_any_dtype(dtype) or isinstance(
            dtype,
            pd.DatetimeTZDtype,
        ):
            export[column] = export[column].map(format_timestamp)

    export.to_csv(output_path, index=False)
    return output_path


def write_json(payload: dict[str, Any], path: str | Path) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )
    return output_path


def format_timestamp(value: Any) -> str:
    if pd.isna(value):
        return ""
    timestamp = pd.Timestamp(value)
    if timestamp.tzinfo is None:
        timestamp = timestamp.tz_localize("UTC")
    else:
        timestamp = timestamp.tz_convert("UTC")
    return timestamp.isoformat().replace("+00:00", "Z")
