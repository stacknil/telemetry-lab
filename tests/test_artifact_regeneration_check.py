from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from telemetry_lab.manifest import digest_file_bytes, digest_files


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "regenerate_artifacts.py"
LF_GENERATED_OUTPUTS = (
    "data/processed/run_manifest.json",
    "data/processed/richer_sample/run_manifest.json",
    "demos/ai-assisted-detection-demo/artifacts/case_report.md",
    "demos/ai-assisted-detection-demo/artifacts/run_manifest.json",
    "demos/rule-evaluation-and-dedup-demo/artifacts/dedup_report.md",
    "demos/rule-evaluation-and-dedup-demo/artifacts/run_manifest.json",
    "demos/config-change-investigation-demo/artifacts/investigation_report.md",
    "demos/config-change-investigation-demo/artifacts/run_manifest.json",
    "demos/cloud-iam-change-investigation-demo/artifacts/investigation_report.md",
    "demos/cloud-iam-change-investigation-demo/artifacts/run_manifest.json",
)


def _load_regeneration_script():
    spec = importlib.util.spec_from_file_location(
        "regenerate_artifacts",
        SCRIPT_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_regenerate_artifacts_check_matches_committed_outputs() -> None:
    script = _load_regeneration_script()

    exit_code = script.main(
        [
            "--check",
            "--work-dir",
            ".artifact-regeneration-tmp/pytest",
            "--no-clean",
        ]
    )

    assert exit_code == 0


def test_generated_lf_outputs_are_pinned_for_clean_clone_rewrites() -> None:
    result = subprocess.run(
        ["git", "check-attr", "eol", "--", *LF_GENERATED_OUTPUTS],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=True,
    )

    assert result.stdout.splitlines() == [
        f"{path}: eol: lf" for path in LF_GENERATED_OUTPUTS
    ]
    for path in LF_GENERATED_OUTPUTS:
        assert b"\r\n" not in (REPO_ROOT / path).read_bytes(), path


def test_window_regeneration_hashes_the_shipped_config_bytes(tmp_path) -> None:
    script = _load_regeneration_script()
    config_path = REPO_ROOT / "configs" / "default.yaml"

    artifacts = script._run_window_pipeline_job(
        tmp_path,
        config_path=config_path,
        committed_root=REPO_ROOT / "data" / "processed",
    )
    manifest = json.loads(
        (artifacts.generated_root / "run_manifest.json").read_text(
            encoding="utf-8"
        )
    )

    assert manifest["config_digest"] == digest_files(
        {config_path.name: config_path}
    )
    assert manifest["input_file_digests"] == {
        "data/raw/sample_events.jsonl": digest_file_bytes(
            REPO_ROOT / "data" / "raw" / "sample_events.jsonl"
        )
    }
    assert manifest["config_file_digests"] == {
        "configs/default.yaml": digest_file_bytes(config_path)
    }


def test_regenerate_artifacts_reports_mismatched_strict_artifact(tmp_path) -> None:
    script = _load_regeneration_script()
    committed_root = tmp_path / "committed"
    generated_root = tmp_path / "generated"
    committed_root.mkdir()
    generated_root.mkdir()
    (committed_root / "artifact.json").write_text('{"status":"old"}\n', encoding="utf-8")
    (generated_root / "artifact.json").write_text('{"status":"new"}\n', encoding="utf-8")

    artifact_set = script.ArtifactSet(
        name="test",
        committed_root=committed_root,
        generated_root=generated_root,
        strict_paths=(Path("artifact.json"),),
    )

    differences = script.compare_artifact_set("test", artifact_set)

    assert len(differences) == 1
    assert differences[0].reason == "content differs"
