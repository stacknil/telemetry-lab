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


def test_load_events_requires_required_fields(tmp_path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"timestamp":"2026-03-10T10:00:00Z","event_type":"login_success"}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Missing required event fields"):
        load_events(path)

