from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import yaml

from telemetry_window_demo.io import load_config


def _cli_env(repo_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    src_path = str(repo_root / "src")
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        src_path
        if not existing_pythonpath
        else os.pathsep.join((src_path, existing_pythonpath))
    )
    return env


def test_readme_summarize_command_runs_as_module() -> None:
    repo_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "telemetry_window_demo.cli",
            "summarize",
            "--input",
            "data/raw/sample_events.jsonl",
        ],
        cwd=repo_root,
        env=_cli_env(repo_root),
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "events: 41" in result.stdout
    assert "overall_error_rate: 0.61" in result.stdout


def test_readme_default_run_command_writes_expected_artifacts(tmp_path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    config = load_config(repo_root / "configs" / "default.yaml")
    output_dir = tmp_path / "processed"
    config["input_path"] = str((repo_root / "data" / "raw" / "sample_events.jsonl").resolve())
    config["output_dir"] = str(output_dir.resolve())
    config_path = tmp_path / "default.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "telemetry_window_demo.cli",
            "run",
            "--config",
            str(config_path),
        ],
        cwd=repo_root,
        env=_cli_env(repo_root),
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "[OK] Loaded 41 events" in result.stdout
    assert "[OK] Triggered 12 alerts" in result.stdout
    assert (output_dir / "features.csv").is_file()
    assert (output_dir / "alerts.csv").is_file()
    assert (output_dir / "summary.json").is_file()
    assert (output_dir / "event_count_timeline.png").is_file()


def test_plot_command_runs_as_module(tmp_path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    output_dir = tmp_path / "plots"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "telemetry_window_demo.cli",
            "plot",
            "--features",
            "data/processed/features.csv",
            "--alerts",
            "data/processed/alerts.csv",
            "--output-dir",
            str(output_dir),
        ],
        cwd=repo_root,
        env=_cli_env(repo_root),
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "[OK] Saved plots to" in result.stdout
    assert (output_dir / "event_count_timeline.png").is_file()
    assert (output_dir / "error_rate_timeline.png").is_file()
    assert (output_dir / "alerts_timeline.png").is_file()


def test_cloud_iam_demo_command_runs_as_module() -> None:
    repo_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "telemetry_window_demo.cli",
            "run-cloud-iam-change-demo",
        ],
        cwd=repo_root,
        env=_cli_env(repo_root),
        text=True,
        capture_output=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "[OK] Loaded 14 CloudTrail-like events" in result.stdout
    assert "[OK] Built 5 investigation signals" in result.stdout
    assert (
        repo_root
        / "demos"
        / "cloud-iam-change-investigation-demo"
        / "artifacts"
        / "investigation_report.md"
    ).is_file()
