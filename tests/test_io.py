from __future__ import annotations

import pytest

from telemetry_window_demo.io import load_events


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

