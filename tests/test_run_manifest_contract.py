from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from telemetry_lab.run_manifest_contract import (
    RunManifestVersionError,
    select_run_manifest_schema,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = REPO_ROOT / "tests" / "fixtures" / "run_manifests"


def _load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("fixture_name", "schema_version", "schema_path", "incompatible_schema_path"),
    [
        (
            "v1.json",
            "run-manifest/v1",
            "schemas/run_manifest.schema.json",
            "schemas/run_manifest.v2.schema.json",
        ),
        (
            "v2.json",
            "run-manifest/v2",
            "schemas/run_manifest.v2.schema.json",
            "schemas/run_manifest.schema.json",
        ),
    ],
)
def test_select_run_manifest_schema_uses_exact_compatible_version(
    fixture_name: str,
    schema_version: str,
    schema_path: str,
    incompatible_schema_path: str,
) -> None:
    manifest = _load_json(FIXTURE_ROOT / fixture_name)

    selection = select_run_manifest_schema(manifest)

    assert selection.schema_version == schema_version
    assert selection.schema_path.as_posix() == schema_path

    selected_schema = _load_json(REPO_ROOT / selection.schema_path)
    incompatible_schema = _load_json(REPO_ROOT / incompatible_schema_path)
    selected_validator = Draft202012Validator(
        selected_schema,
        format_checker=FormatChecker(),
    )
    incompatible_validator = Draft202012Validator(
        incompatible_schema,
        format_checker=FormatChecker(),
    )

    assert list(selected_validator.iter_errors(manifest)) == []
    assert list(incompatible_validator.iter_errors(manifest))


@pytest.mark.parametrize(
    ("manifest", "message"),
    [
        ([], "run manifest must be a JSON object"),
        ({}, "artifact_schema_versions must be a JSON object"),
        (
            {"artifact_schema_versions": []},
            "artifact_schema_versions must be a JSON object",
        ),
        (
            {"artifact_schema_versions": {}},
            "artifact_schema_versions.run_manifest is required",
        ),
        (
            {"artifact_schema_versions": {"run_manifest": None}},
            "artifact_schema_versions.run_manifest must be a non-empty string",
        ),
        (
            {"artifact_schema_versions": {"run_manifest": "   "}},
            "artifact_schema_versions.run_manifest must be a non-empty string",
        ),
    ],
)
def test_select_run_manifest_schema_rejects_missing_or_invalid_markers(
    manifest: object,
    message: str,
) -> None:
    with pytest.raises(RunManifestVersionError, match=message):
        select_run_manifest_schema(manifest)


@pytest.mark.parametrize(
    "schema_version",
    ["run-manifest/v3", "run-manifest/v2 ", "RUN-MANIFEST/V2"],
)
def test_select_run_manifest_schema_rejects_unknown_versions_without_fallback(
    schema_version: str,
) -> None:
    manifest = {"artifact_schema_versions": {"run_manifest": schema_version}}

    with pytest.raises(RunManifestVersionError) as exc_info:
        select_run_manifest_schema(manifest)

    assert str(exc_info.value) == (
        f"unsupported run manifest schema version {schema_version!r}; "
        "supported versions: run-manifest/v1, run-manifest/v2"
    )


@pytest.mark.parametrize(
    ("fixture_name", "schema_version", "schema_path"),
    [
        ("v1.json", "run-manifest/v1", "schemas/run_manifest.schema.json"),
        ("v2.json", "run-manifest/v2", "schemas/run_manifest.v2.schema.json"),
    ],
)
def test_validate_run_manifest_script_reports_selected_contract(
    fixture_name: str,
    schema_version: str,
    schema_path: str,
) -> None:
    fixture_path = FIXTURE_ROOT / fixture_name

    result = subprocess.run(
        [sys.executable, "scripts/validate_run_manifest.py", str(fixture_path)],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert f"{schema_version} -> {schema_path}" in result.stdout


def test_validate_run_manifest_script_rejects_unknown_version(tmp_path: Path) -> None:
    manifest_path = tmp_path / "unknown.json"
    manifest_path.write_text(
        json.dumps(
            {"artifact_schema_versions": {"run_manifest": "run-manifest/v3"}}
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "scripts/validate_run_manifest.py", str(manifest_path)],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "unsupported run manifest schema version 'run-manifest/v3'" in result.stderr
