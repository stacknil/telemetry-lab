from __future__ import annotations

from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest
import yaml

from telemetry_window_demo.cli import run_command
from telemetry_window_demo.io import load_config


def _base_config(tmp_path: Path) -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[1]
    config = load_config(repo_root / "configs" / "default.yaml")
    config["input_path"] = str((repo_root / "data" / "raw" / "sample_events.jsonl").resolve())
    config["output_dir"] = str((tmp_path / "processed").resolve())
    return config


def _write_config(tmp_path: Path, config: dict[str, Any]) -> Path:
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text(
        yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8",
    )
    return config_path


def test_run_config_requires_input_path(tmp_path) -> None:
    config = _base_config(tmp_path)
    del config["input_path"]
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="input_path"):
        run_command(Namespace(config=str(config_path)))


def test_run_config_rejects_boolean_window_size(tmp_path) -> None:
    config = _base_config(tmp_path)
    config["time"]["window_size_seconds"] = True
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="time.window_size_seconds"):
        run_command(Namespace(config=str(config_path)))


def test_run_config_rejects_non_positive_step_size(tmp_path) -> None:
    config = _base_config(tmp_path)
    config["time"]["step_size_seconds"] = 0
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="time.step_size_seconds"):
        run_command(Namespace(config=str(config_path)))


def test_run_config_rejects_string_feature_list(tmp_path) -> None:
    config = _base_config(tmp_path)
    config["features"]["count_event_types"] = "login_fail"
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="features.count_event_types"):
        run_command(Namespace(config=str(config_path)))


def test_run_config_rejects_boolean_cooldown(tmp_path) -> None:
    config = _base_config(tmp_path)
    config["rules"]["cooldown_seconds"] = True
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="rules.cooldown_seconds"):
        run_command(Namespace(config=str(config_path)))


def test_run_config_rejects_non_mapping_rule_section(tmp_path) -> None:
    config = _base_config(tmp_path)
    config["rules"]["high_error_rate"] = True
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="rules.high_error_rate"):
        run_command(Namespace(config=str(config_path)))


def test_run_config_rejects_string_rare_event_types(tmp_path) -> None:
    config = _base_config(tmp_path)
    config["rules"]["rare_event_repeat"]["event_types"] = "malware_alert"
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="rules.rare_event_repeat.event_types"):
        run_command(Namespace(config=str(config_path)))


def test_run_config_rejects_unknown_rule_name(tmp_path) -> None:
    config = _base_config(tmp_path)
    config["rules"]["high_error_rates"] = {"threshold": 0.30}
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="high_error_rates"):
        run_command(Namespace(config=str(config_path)))


def test_run_config_rejects_unknown_rule_field(tmp_path) -> None:
    config = _base_config(tmp_path)
    config["rules"]["high_error_rate"]["thresholds"] = 0.30
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="rules.high_error_rate"):
        run_command(Namespace(config=str(config_path)))


def test_run_config_rejects_boolean_rule_threshold(tmp_path) -> None:
    config = _base_config(tmp_path)
    config["rules"]["high_error_rate"]["threshold"] = True
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="rules.high_error_rate.threshold"):
        run_command(Namespace(config=str(config_path)))


def test_run_config_rejects_non_positive_count_threshold(tmp_path) -> None:
    config = _base_config(tmp_path)
    config["rules"]["login_fail_burst"]["threshold"] = 0
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="rules.login_fail_burst.threshold"):
        run_command(Namespace(config=str(config_path)))


def test_run_config_rejects_source_spread_multiplier_below_one(tmp_path) -> None:
    config = _base_config(tmp_path)
    config["rules"]["source_spread_spike"]["multiplier"] = 0.5
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="rules.source_spread_spike.multiplier"):
        run_command(Namespace(config=str(config_path)))


def test_run_config_rejects_empty_rule_severity(tmp_path) -> None:
    config = _base_config(tmp_path)
    config["rules"]["persistent_high_error"]["severity"] = ""
    config_path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="rules.persistent_high_error.severity"):
        run_command(Namespace(config=str(config_path)))
