from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path

import pandas as pd
import yaml

from telemetry_lab.cli import run_command
from telemetry_lab.io import load_alert_table, load_config, load_feature_table


def _load_summary(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_manifest(path: Path) -> dict[str, object]:
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
    generated_manifest = _load_manifest(generated_output_dir / "run_manifest.json")
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
        "run_manifest.json",
        "event_count_timeline.png",
        "error_rate_timeline.png",
        "alerts_timeline.png",
    }
    assert generated_manifest["tool_version"] == "1.2.0"
    assert generated_manifest["demo_id"] == "window"
    assert generated_manifest["execution_mode"] == "synthetic-local"
    assert generated_manifest["input_digest"].startswith("sha256:")
    assert generated_manifest["config_digest"].startswith("sha256:")
    assert generated_manifest["artifact_schema_versions"]["run_manifest"] == (
        "run-manifest/v1"
    )

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
        "run_manifest.json",
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


def test_pipeline_writes_summary_when_rules_are_null(tmp_path, capsys) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    config_path = repo_root / "configs" / "default.yaml"
    generated_output_dir = tmp_path / "null_rules"

    config = load_config(config_path)
    config["input_path"] = str((repo_root / "data" / "raw" / "sample_events.jsonl").resolve())
    config["output_dir"] = str(generated_output_dir.resolve())
    config["rules"] = None

    temp_config_path = tmp_path / "null_rules.yaml"
    temp_config_path.write_text(
        yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8",
    )

    run_command(Namespace(config=str(temp_config_path)))

    generated_alerts = load_alert_table(generated_output_dir / "alerts.csv")
    generated_summary = _load_summary(generated_output_dir / "summary.json")

    assert generated_summary["cooldown_seconds"] == 0
    assert generated_summary["alert_count"] == len(generated_alerts)
    assert Path(generated_summary["input_path"]).name == "sample_events.jsonl"
    assert Path(generated_summary["output_dir"]).name == "null_rules"
    assert _artifact_names(generated_summary) == {
        "features.csv",
        "alerts.csv",
        "summary.json",
        "run_manifest.json",
        "event_count_timeline.png",
        "error_rate_timeline.png",
        "alerts_timeline.png",
    }
    assert (generated_output_dir / "summary.json").exists()
    assert (generated_output_dir / "run_manifest.json").exists()

    stdout = capsys.readouterr().out
    assert "[OK] Loaded 41 events" in stdout


def test_pipeline_honors_configured_timestamp_column(tmp_path, capsys) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    config = load_config(repo_root / "configs" / "default.yaml")
    generated_output_dir = tmp_path / "custom_time"
    input_path = tmp_path / "custom_time_events.csv"
    input_path.write_text(
        "event_time,event_type,source,target,status,severity\n"
        "2026-03-10T10:00:00Z,login_fail,user_a,auth,fail,high\n"
        "2026-03-10T10:00:10Z,login_success,user_a,auth,ok,low\n",
        encoding="utf-8",
    )
    config["input_path"] = str(input_path.resolve())
    config["output_dir"] = str(generated_output_dir.resolve())
    config["time"]["timestamp_col"] = "event_time"

    temp_config_path = tmp_path / "custom_time.yaml"
    temp_config_path.write_text(
        yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8",
    )

    run_command(Namespace(config=str(temp_config_path)))

    generated_features = load_feature_table(generated_output_dir / "features.csv")
    generated_summary = _load_summary(generated_output_dir / "summary.json")

    assert len(generated_features) == 2
    assert generated_features.loc[0, "event_count"] == 2
    assert generated_summary["normalized_event_count"] == 2
    assert generated_summary["window_count"] == 2

    stdout = capsys.readouterr().out
    assert "[OK] Loaded 2 events" in stdout
