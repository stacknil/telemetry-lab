from __future__ import annotations

from telemetry_window_demo.cli import main


def test_summarize_honors_configured_timestamp_column(tmp_path, capsys) -> None:
    input_path = tmp_path / "events.csv"
    input_path.write_text(
        "event_time,event_type,source,target,status,severity\n"
        "2026-03-10T10:00:10Z,login_success,user_a,auth,ok,low\n"
        "2026-03-10T10:00:00Z,login_fail,user_b,auth,fail,high\n",
        encoding="utf-8",
    )

    main(
        [
            "summarize",
            "--input",
            str(input_path),
            "--timestamp-col",
            "event_time",
        ]
    )

    stdout = capsys.readouterr().out
    assert "events: 2" in stdout
    assert "time_range: 2026-03-10T10:00:00Z -> 2026-03-10T10:00:10Z" in stdout
    assert "unique_sources: 2" in stdout
    assert "overall_error_rate: 0.50" in stdout
