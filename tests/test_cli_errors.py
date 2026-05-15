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
