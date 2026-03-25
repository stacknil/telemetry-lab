from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

import pandas as pd
import yaml

from telemetry_window_demo.cli import run_command
from telemetry_window_demo.io import load_alert_table, load_config, load_feature_table


def _load_summary(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _artifact_names(summary: dict[str, object]) -> set[str]:
    return {Path(path).name for path in summary["generated_artifacts"]}


def test_default_pipeline_reproduces_sample_outputs(tmp_path, capsys) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    config_path = repo_root / "configs" / "default.yaml"
    expected_output_dir = repo_root / "data" / "processed"
    generated_output_dir = tmp_path / "processed"

    config = load_config(config_path)
    config["input_path"] = str((repo_root / "data" / "raw" / "sample_events.jsonl").resolve())
    config["output_dir"] = str(generated_output_dir.resolve())

    temp_config_path = tmp_path / "default.yaml"
    temp_config_path.write_text(
        yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8",
    )

    run_command(Namespace(config=str(temp_config_path)))

    generated_features = load_feature_table(generated_output_dir / "features.csv")
    generated_alerts = load_alert_table(generated_output_dir / "alerts.csv")
    generated_summary = _load_summary(generated_output_dir / "summary.json")
    expected_features = load_feature_table(expected_output_dir / "features.csv")
    expected_alerts = load_alert_table(expected_output_dir / "alerts.csv")
    expected_summary = _load_summary(expected_output_dir / "summary.json")

    assert len(generated_features) == 24
    assert len(generated_alerts) == 12
    pd.testing.assert_frame_equal(generated_features, expected_features)
    pd.testing.assert_frame_equal(generated_alerts, expected_alerts)
    assert generated_summary["normalized_event_count"] == 41
    assert generated_summary["window_count"] == 24
    assert generated_summary["feature_row_count"] == 24
    assert generated_summary["alert_count"] == 12
    assert generated_summary["cooldown_seconds"] == 60
    assert generated_summary["triggered_rule_names"] == expected_summary["triggered_rule_names"]
    assert generated_summary["triggered_rule_counts"] == expected_summary["triggered_rule_counts"]
    assert Path(generated_summary["input_path"]).name == "sample_events.jsonl"
    assert Path(generated_summary["output_dir"]).name == "processed"
    assert _artifact_names(generated_summary) == {
        "features.csv",
        "alerts.csv",
        "summary.json",
        "event_count_timeline.png",
        "error_rate_timeline.png",
        "alerts_timeline.png",
    }

    for file_name in (
        "event_count_timeline.png",
        "error_rate_timeline.png",
        "alerts_timeline.png",
        "summary.json",
    ):
        assert (generated_output_dir / file_name).exists()

    stdout = capsys.readouterr().out
    assert "[OK] Loaded 41 events" in stdout
    assert "[OK] Triggered 12 alerts" in stdout


def test_richer_sample_pipeline_reproduces_sample_outputs(tmp_path, capsys) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    config_path = repo_root / "configs" / "richer_sample.yaml"
    expected_output_dir = repo_root / "data" / "processed" / "richer_sample"
    generated_output_dir = tmp_path / "richer_sample"

    config = load_config(config_path)
    config["input_path"] = str(
        (repo_root / "data" / "raw" / "richer_sample_events.jsonl").resolve()
    )
    config["output_dir"] = str(generated_output_dir.resolve())

    temp_config_path = tmp_path / "richer_sample.yaml"
    temp_config_path.write_text(
        yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8",
    )

    run_command(Namespace(config=str(temp_config_path)))

    generated_features = load_feature_table(generated_output_dir / "features.csv")
    generated_alerts = load_alert_table(generated_output_dir / "alerts.csv")
    generated_summary = _load_summary(generated_output_dir / "summary.json")
    expected_features = load_feature_table(expected_output_dir / "features.csv")
    expected_alerts = load_alert_table(expected_output_dir / "alerts.csv")
    expected_summary = _load_summary(expected_output_dir / "summary.json")

    assert len(generated_features) == 24
    assert len(generated_alerts) == 8
    pd.testing.assert_frame_equal(generated_features, expected_features)
    pd.testing.assert_frame_equal(generated_alerts, expected_alerts)
    assert generated_summary["normalized_event_count"] == 28
    assert generated_summary["window_count"] == 24
    assert generated_summary["feature_row_count"] == 24
    assert generated_summary["alert_count"] == 8
    assert generated_summary["cooldown_seconds"] == 120
    assert generated_summary["triggered_rule_names"] == expected_summary["triggered_rule_names"]
    assert generated_summary["triggered_rule_counts"] == expected_summary["triggered_rule_counts"]
    assert Path(generated_summary["input_path"]).name == "richer_sample_events.jsonl"
    assert Path(generated_summary["output_dir"]).name == "richer_sample"
    assert _artifact_names(generated_summary) == {
        "features.csv",
        "alerts.csv",
        "summary.json",
        "event_count_timeline.png",
        "error_rate_timeline.png",
        "alerts_timeline.png",
    }

    for file_name in (
        "event_count_timeline.png",
        "error_rate_timeline.png",
        "alerts_timeline.png",
        "summary.json",
    ):
        assert (generated_output_dir / file_name).exists()

    stdout = capsys.readouterr().out
    assert "[OK] Loaded 28 events" in stdout
    assert "[OK] Triggered 8 alerts" in stdout
