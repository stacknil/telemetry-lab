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
FEATURE_TABLE_NUMERIC_COLUMNS = (
    ("event_count", 0.0, None, True),
    ("error_rate", 0.0, 1.0, False),
)
ALERT_TABLE_REQUIRED_COLUMNS = (
    "alert_time",
    "window_start",
    "window_end",
    "rule_name",
    "severity",
)
ALERT_TABLE_DATETIME_COLUMNS = ("alert_time", "window_start", "window_end")
ALERT_TABLE_TEXT_COLUMNS = ("rule_name", "severity")


def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    _require_existing_file(config_path, display_name="Config file")
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


def load_events(path: str | Path, *, timestamp_col: str = "timestamp") -> pd.DataFrame:
    input_path = Path(path)
    _require_existing_file(input_path, display_name="Input file")

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

    validate_event_frame(events, source=str(input_path), timestamp_col=timestamp_col)
    return events


def load_feature_table(path: str | Path) -> pd.DataFrame:
    table_path = Path(path)
    frame = _read_csv_table(table_path, table_name="feature table")
    _require_columns(frame, FEATURE_TABLE_REQUIRED_COLUMNS, source=str(table_path))
    _parse_datetime_columns(
        frame,
        FEATURE_TABLE_DATETIME_COLUMNS,
        source=str(table_path),
    )
    _parse_numeric_columns(
        frame,
        FEATURE_TABLE_NUMERIC_COLUMNS,
        source=str(table_path),
    )
    _require_window_bounds(frame, source=str(table_path))
    return frame


def load_alert_table(path: str | Path) -> pd.DataFrame:
    table_path = Path(path)
    frame = _read_csv_table(table_path, table_name="alert table")
    _require_columns(frame, ALERT_TABLE_REQUIRED_COLUMNS, source=str(table_path))
    _parse_datetime_columns(
        frame,
        ALERT_TABLE_DATETIME_COLUMNS,
        source=str(table_path),
    )
    _require_window_bounds(frame, source=str(table_path))
    _require_alert_time_bounds(frame, source=str(table_path))
    _require_text_columns(frame, ALERT_TABLE_TEXT_COLUMNS, source=str(table_path))
    return frame


def _read_csv_table(table_path: Path, *, table_name: str) -> pd.DataFrame:
    display_name = table_name[:1].upper() + table_name[1:]
    _require_existing_file(table_path, display_name=display_name)
    try:
        return pd.read_csv(table_path)
    except (
        pd.errors.EmptyDataError,
        pd.errors.ParserError,
        UnicodeDecodeError,
    ) as exc:
        raise ValueError(f"Invalid {table_name} CSV in {table_path}: {exc}") from exc


def _require_existing_file(file_path: Path, *, display_name: str) -> None:
    if not file_path.exists():
        raise FileNotFoundError(f"{display_name} not found: {file_path}")
    if not file_path.is_file():
        raise ValueError(f"{display_name} path is not a file: {file_path}")


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


def _parse_numeric_columns(
    frame: pd.DataFrame,
    numeric_columns: tuple[tuple[str, float, float | None, bool], ...],
    *,
    source: str,
) -> None:
    for column, minimum, maximum, require_integer in numeric_columns:
        try:
            parsed = pd.to_numeric(frame[column], errors="raise")
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Invalid numeric values in {source}: {column}"
            ) from exc

        if parsed.isna().any():
            raise ValueError(f"Missing numeric values in {source}: {column}")
        if (parsed < minimum).any():
            raise ValueError(
                f"Numeric values in {source} must be at least {minimum:g}: {column}"
            )
        if maximum is not None and (parsed > maximum).any():
            raise ValueError(
                f"Numeric values in {source} must be at most {maximum:g}: {column}"
            )
        if require_integer and not (parsed % 1 == 0).all():
            raise ValueError(
                f"Numeric values in {source} must be whole numbers: {column}"
            )

        frame[column] = parsed.astype("int64" if require_integer else "float64")


def _require_window_bounds(frame: pd.DataFrame, *, source: str) -> None:
    invalid_windows = frame["window_end"] <= frame["window_start"]
    if invalid_windows.any():
        raise ValueError(
            f"Window end must be after window start in {source}: "
            f"{int(invalid_windows.sum())} row(s)"
        )


def _require_alert_time_bounds(frame: pd.DataFrame, *, source: str) -> None:
    out_of_bounds = (frame["alert_time"] < frame["window_start"]) | (
        frame["alert_time"] > frame["window_end"]
    )
    if out_of_bounds.any():
        raise ValueError(
            f"Alert time must fall within window bounds in {source}: "
            f"{int(out_of_bounds.sum())} row(s)"
        )


def _require_text_columns(
    frame: pd.DataFrame,
    text_columns: tuple[str, ...],
    *,
    source: str,
) -> None:
    for column in text_columns:
        empty_values = (
            frame[column].isna() | frame[column].astype(str).str.strip().eq("")
        )
        if empty_values.any():
            raise ValueError(f"Missing text values in {source}: {column}")


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
