from __future__ import annotations

import pytest
import yaml

from telemetry_window_demo.cli import main


def test_main_reports_config_errors_without_traceback(tmp_path, capsys) -> None:
    config_path = tmp_path / "missing-input-path.yaml"
    config_path.write_text(
        yaml.safe_dump({"output_dir": str(tmp_path / "processed")}),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        main(["run", "--config", str(config_path)])

    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert stderr.startswith("error: ")
    assert "input_path" in stderr
    assert "Traceback" not in stderr


def test_main_reports_missing_config_without_traceback(tmp_path, capsys) -> None:
    config_path = tmp_path / "missing.yaml"

    with pytest.raises(SystemExit) as excinfo:
        main(["run", "--config", str(config_path)])

    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert stderr.startswith("error: ")
    assert "Config file not found" in stderr
    assert "Traceback" not in stderr


def test_main_reports_invalid_yaml_config_without_traceback(tmp_path, capsys) -> None:
    config_path = tmp_path / "broken.yaml"
    config_path.write_text("input_path: [\n", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        main(["run", "--config", str(config_path)])

    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert stderr.startswith("error: ")
    assert "Invalid YAML config" in stderr
    assert "Traceback" not in stderr


def test_main_reports_directory_input_without_traceback(tmp_path, capsys) -> None:
    config_path = tmp_path / "directory-input.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "input_path": str(tmp_path),
                "output_dir": str(tmp_path / "processed"),
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        main(["run", "--config", str(config_path)])

    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert stderr.startswith("error: ")
    assert "Input file path is not a file" in stderr
    assert "Traceback" not in stderr


def test_main_reports_bad_plot_feature_table_without_traceback(tmp_path, capsys) -> None:
    features_path = tmp_path / "features.csv"
    features_path.write_text(
        "window_start,window_end,error_rate\n"
        "2026-03-10T10:00:00Z,2026-03-10T10:01:00Z,0.25\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        main(["plot", "--features", str(features_path)])

    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert stderr.startswith("error: ")
    assert "event_count" in stderr
    assert "Traceback" not in stderr


def test_main_reports_bad_plot_feature_value_without_traceback(tmp_path, capsys) -> None:
    features_path = tmp_path / "features.csv"
    features_path.write_text(
        "window_start,window_end,event_count,error_rate\n"
        "2026-03-10T10:00:00Z,2026-03-10T10:01:00Z,not-a-count,0.25\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        main(["plot", "--features", str(features_path)])

    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert stderr.startswith("error: ")
    assert "Invalid numeric values" in stderr
    assert "event_count" in stderr
    assert "Traceback" not in stderr


def test_main_reports_missing_default_alert_table_without_traceback(tmp_path, capsys) -> None:
    features_path = tmp_path / "features.csv"
    features_path.write_text(
        "window_start,window_end,event_count,error_rate\n"
        "2026-03-10T10:00:00Z,2026-03-10T10:01:00Z,10,0.25\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        main(["plot", "--features", str(features_path)])

    assert excinfo.value.code == 1
    stderr = capsys.readouterr().err
    assert stderr.startswith("error: ")
    assert "Alert table not found" in stderr
    assert "Traceback" not in stderr
