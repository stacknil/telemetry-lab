from __future__ import annotations

from argparse import Namespace
from pathlib import Path

import pandas as pd
import yaml

from telemetry_window_demo.cli import run_command
from telemetry_window_demo.io import load_alert_table, load_config, load_feature_table


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
    expected_features = load_feature_table(expected_output_dir / "features.csv")
    expected_alerts = load_alert_table(expected_output_dir / "alerts.csv")

    assert len(generated_features) == 24
    assert len(generated_alerts) == 12
    pd.testing.assert_frame_equal(generated_features, expected_features)
    pd.testing.assert_frame_equal(generated_alerts, expected_alerts)

    for file_name in (
        "event_count_timeline.png",
        "error_rate_timeline.png",
        "alerts_timeline.png",
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
    expected_features = load_feature_table(expected_output_dir / "features.csv")
    expected_alerts = load_alert_table(expected_output_dir / "alerts.csv")

    assert len(generated_features) == 24
    assert len(generated_alerts) == 8
    pd.testing.assert_frame_equal(generated_features, expected_features)
    pd.testing.assert_frame_equal(generated_alerts, expected_alerts)

    for file_name in (
        "event_count_timeline.png",
        "error_rate_timeline.png",
        "alerts_timeline.png",
    ):
        assert (generated_output_dir / file_name).exists()

    stdout = capsys.readouterr().out
    assert "[OK] Loaded 28 events" in stdout
    assert "[OK] Triggered 8 alerts" in stdout
