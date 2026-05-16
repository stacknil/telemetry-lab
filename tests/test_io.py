from __future__ import annotations

import pytest

from telemetry_window_demo.io import (
    load_alert_table,
    load_config,
    load_events,
    load_feature_table,
)


def test_load_config_reports_missing_file(tmp_path) -> None:
    path = tmp_path / "missing.yaml"

    with pytest.raises(FileNotFoundError, match="Config file not found"):
        load_config(path)


def test_load_config_rejects_invalid_yaml(tmp_path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text("input_path: [\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid YAML config"):
        load_config(path)


def test_load_events_from_jsonl(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        (
            '{"timestamp":"2026-03-10T10:00:00Z","event_type":"login_success",'
            '"source":"user_a","target":"auth","status":"ok"}\n'
        ),
        encoding="utf-8",
    )

    frame = load_events(path)

    assert len(frame) == 1
    assert frame.loc[0, "event_type"] == "login_success"


def test_load_events_from_csv(tmp_path) -> None:
    path = tmp_path / "events.csv"
    path.write_text(
        "timestamp,event_type,source,target,status\n"
        "2026-03-10T10:00:00Z,login_success,user_a,auth,ok\n",
        encoding="utf-8",
    )

    frame = load_events(path)

    assert len(frame) == 1
    assert frame.loc[0, "event_type"] == "login_success"


def test_load_events_from_csv_preserves_na_like_required_values(tmp_path) -> None:
    path = tmp_path / "events.csv"
    path.write_text(
        "timestamp,event_type,source,target,status\n"
        "2026-03-10T10:00:00Z,login_success,user_a,NA,ok\n"
        "2026-03-10T10:00:10Z,login_fail,user_b,null,fail\n",
        encoding="utf-8",
    )

    frame = load_events(path)

    assert len(frame) == 2
    assert list(frame["target"]) == ["NA", "null"]


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        (
            "events.jsonl",
            '{"timestamp":"2026-03-10T10:00:00Z","event_type":"login_success"}\n',
        ),
        (
            "events.csv",
            "timestamp,event_type\n"
            "2026-03-10T10:00:00Z,login_success\n",
        ),
    ],
)
def test_load_events_requires_required_fields(filename, content, tmp_path) -> None:
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        load_events(path)

    message = str(excinfo.value)
    assert "Missing required event fields" in message
    assert "source" in message
    assert "target" in message
    assert "status" in message


def test_load_events_rejects_malformed_jsonl(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        (
            '{"timestamp":"2026-03-10T10:00:00Z","event_type":"login_success",'
            '"source":"user_a","target":"auth","status":"ok"\n'
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        load_events(path)

    message = str(excinfo.value)
    assert "Invalid JSONL" in message
    assert "line 1" in message


def test_load_events_rejects_malformed_csv(tmp_path) -> None:
    path = tmp_path / "events.csv"
    path.write_text(
        'timestamp,event_type,source,target,status\n'
        '"2026-03-10T10:00:00Z,login_success,user_a,auth,ok\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid CSV"):
        load_events(path)


@pytest.mark.parametrize(
    ("filename", "content"),
    [
        (
            "events.jsonl",
            (
                '{"timestamp":"2026-03-10T10:00:00Z","event_type":"login_success",'
                '"source":"user_a","target":"auth","status":"ok"}\n'
                '{"timestamp":"2026-03-10T10:00:10Z","event_type":"login_fail",'
                '"source":"user_b","status":"fail"}\n'
            ),
        ),
        (
            "events.csv",
            "timestamp,event_type,source,target,status\n"
            "2026-03-10T10:00:00Z,login_success,user_a,auth,ok\n"
            "2026-03-10T10:00:10Z,login_fail,user_b,,fail\n",
        ),
    ],
)
def test_load_events_rejects_missing_required_values(filename, content, tmp_path) -> None:
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError) as excinfo:
        load_events(path)

    message = str(excinfo.value)
    assert "Missing required event values" in message
    assert "target (1 row(s))" in message


def test_load_feature_table_requires_plot_columns(tmp_path) -> None:
    path = tmp_path / "features.csv"
    path.write_text(
        "window_start,window_end,error_rate\n"
        "2026-03-10T10:00:00Z,2026-03-10T10:01:00Z,0.25\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        load_feature_table(path)

    message = str(excinfo.value)
    assert "Missing required columns" in message
    assert "event_count" in message


def test_load_feature_table_reports_missing_file(tmp_path) -> None:
    path = tmp_path / "missing-features.csv"

    with pytest.raises(FileNotFoundError, match="Feature table not found"):
        load_feature_table(path)


def test_load_feature_table_rejects_invalid_window_timestamp(tmp_path) -> None:
    path = tmp_path / "features.csv"
    path.write_text(
        "window_start,window_end,event_count,error_rate\n"
        "not-a-time,2026-03-10T10:01:00Z,10,0.25\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        load_feature_table(path)

    message = str(excinfo.value)
    assert "Invalid datetime values" in message
    assert "window_start" in message


def test_load_feature_table_rejects_invalid_numeric_value(tmp_path) -> None:
    path = tmp_path / "features.csv"
    path.write_text(
        "window_start,window_end,event_count,error_rate\n"
        "2026-03-10T10:00:00Z,2026-03-10T10:01:00Z,not-a-count,0.25\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        load_feature_table(path)

    message = str(excinfo.value)
    assert "Invalid numeric values" in message
    assert "event_count" in message


def test_load_feature_table_rejects_out_of_range_error_rate(tmp_path) -> None:
    path = tmp_path / "features.csv"
    path.write_text(
        "window_start,window_end,event_count,error_rate\n"
        "2026-03-10T10:00:00Z,2026-03-10T10:01:00Z,10,1.5\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        load_feature_table(path)

    message = str(excinfo.value)
    assert "at most 1" in message
    assert "error_rate" in message


def test_load_alert_table_rejects_invalid_csv(tmp_path) -> None:
    path = tmp_path / "alerts.csv"
    path.write_text(
        'alert_time,window_start,window_end,rule_name,severity\n'
        '"2026-03-10T10:01:00Z,2026-03-10T10:00:00Z,'
        '2026-03-10T10:01:00Z,high_error_rate,medium\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid alert table CSV"):
        load_alert_table(path)


def test_load_alert_table_requires_plot_columns(tmp_path) -> None:
    path = tmp_path / "alerts.csv"
    path.write_text(
        "alert_time,window_start,window_end,severity\n"
        "2026-03-10T10:01:00Z,2026-03-10T10:00:00Z,2026-03-10T10:01:00Z,high\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        load_alert_table(path)

    message = str(excinfo.value)
    assert "Missing required columns" in message
    assert "rule_name" in message


def test_load_alert_table_rejects_missing_alert_timestamp(tmp_path) -> None:
    path = tmp_path / "alerts.csv"
    path.write_text(
        "alert_time,window_start,window_end,rule_name,severity\n"
        ",2026-03-10T10:00:00Z,2026-03-10T10:01:00Z,high_error_rate,medium\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        load_alert_table(path)

    message = str(excinfo.value)
    assert "Missing datetime values" in message
    assert "alert_time" in message


def test_load_alert_table_rejects_missing_rule_name(tmp_path) -> None:
    path = tmp_path / "alerts.csv"
    path.write_text(
        "alert_time,window_start,window_end,rule_name,severity\n"
        "2026-03-10T10:01:00Z,2026-03-10T10:00:00Z,2026-03-10T10:01:00Z,,medium\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as excinfo:
        load_alert_table(path)

    message = str(excinfo.value)
    assert "Missing text values" in message
    assert "rule_name" in message

