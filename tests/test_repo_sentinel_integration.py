from __future__ import annotations

import fnmatch
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_repo_sentinel_ignores_generated_artifacts_only() -> None:
    with (REPO_ROOT / ".reposentinel.toml").open("rb") as config_file:
        config = tomllib.load(config_file)

    assert config["entropy_threshold"] == 4.5
    ignore_globs = config["ignore_globs"]

    assert ignore_globs == [
        ".artifact-regeneration-tmp/**",
        ".pytest-artifacts*/**",
        "data/processed/**",
        "demos/*/artifacts/**",
    ]

    in_scope_paths = [
        "src/telemetry_window_demo/cli.py",
        "configs/default.yaml",
        "data/raw/sample_events.jsonl",
        "demos/config-change-investigation-demo/config/investigation.yaml",
        "demos/config-change-investigation-demo/data/raw/config_changes.jsonl",
    ]
    for path in in_scope_paths:
        assert not any(fnmatch.fnmatchcase(path, pattern) for pattern in ignore_globs)


def test_repo_sentinel_workflow_uses_production_package() -> None:
    workflow = (
        REPO_ROOT / ".github" / "workflows" / "repo-sentinel.yml"
    ).read_text(encoding="utf-8")

    assert "repo-sentinel-lite==0.6.3" in workflow
    assert "--fail-on-severity error" in workflow
