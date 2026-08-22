from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from telemetry_lab.artifact_contract_diff import compare_artifact_trees


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "artifact_contract_diff.py"
SCHEMA_PATH = REPO_ROOT / "schemas" / "artifact_contract_diff.schema.json"


@pytest.fixture
def artifact_roots(tmp_path: Path) -> tuple[Path, Path]:
    expected = tmp_path / "expected"
    actual = tmp_path / "actual"
    expected.mkdir()
    actual.mkdir()
    return expected, actual


def _write_json(path: Path, value: object, *, newline: str = "\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, sort_keys=True) + newline).encode("utf-8"))


def test_compare_artifact_trees_normalizes_text_and_keeps_binary_presence_only(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    (expected / "report.md").write_bytes(b"# Report\r\n\r\nunchanged\r")
    (actual / "report.md").write_bytes(b"# Report\n\nunchanged\n")
    _write_json(expected / "summary.json", {"count": 1}, newline="\r\n")
    _write_json(actual / "summary.json", {"count": 1})
    (expected / "plot.png").write_bytes(b"expected-renderer-bytes")
    (actual / "plot.png").write_bytes(b"actual-renderer-bytes")

    report = compare_artifact_trees(expected, actual).to_dict()

    assert report == {
        "report_schema_version": "artifact-contract-diff/v1",
        "status": "unchanged",
        "summary": {
            "expected_files": 3,
            "actual_files": 3,
            "unchanged_files": 2,
            "missing_files": 0,
            "extra_files": 0,
            "changed_files": 0,
            "presence_only_files": 1,
        },
        "differences": [],
        "presence_only_paths": ["plot.png"],
    }


def test_compare_artifact_trees_reports_missing_and_extra_paths_in_stable_order(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "z-common.json", {"status": "same"})
    _write_json(actual / "z-common.json", {"status": "same"})
    _write_json(expected / "nested" / "a-missing.json", {"status": "old"})
    _write_json(actual / "b-extra.json", {"status": "new"})

    report = compare_artifact_trees(expected, actual).to_dict()

    assert [item["path"] for item in report["differences"]] == [
        "b-extra.json",
        "nested/a-missing.json",
    ]
    assert [item["status"] for item in report["differences"]] == [
        "extra",
        "missing",
    ]
    assert report["differences"][0]["change_reasons"] == ["extra-in-actual"]
    assert report["differences"][1]["change_reasons"] == [
        "missing-from-actual"
    ]
    assert report["summary"] == {
        "expected_files": 2,
        "actual_files": 2,
        "unchanged_files": 1,
        "missing_files": 1,
        "extra_files": 1,
        "changed_files": 0,
        "presence_only_files": 0,
    }


@pytest.mark.parametrize(
    ("name", "expected_bytes", "actual_bytes", "expected_count", "actual_count"),
    [
        (
            "records.json",
            b'[{"id": 1, "status": "old"}]\n',
            b'[{"id": 1, "status": "old"}, {"id": 2, "score": 7}]\n',
            1,
            2,
        ),
        (
            "records.jsonl",
            b'{"id": 1, "status": "old"}\n',
            b'{"id": 1, "status": "old"}\n{"id": 2, "score": 7}\n',
            1,
            2,
        ),
    ],
)
def test_compare_artifact_trees_summarizes_changed_json_records(
    artifact_roots: tuple[Path, Path],
    name: str,
    expected_bytes: bytes,
    actual_bytes: bytes,
    expected_count: int,
    actual_count: int,
) -> None:
    expected, actual = artifact_roots
    (expected / name).write_bytes(expected_bytes)
    (actual / name).write_bytes(actual_bytes)

    difference = compare_artifact_trees(expected, actual).to_dict()["differences"][0]

    assert difference["change_reasons"] == ["content-changed", "structure-changed"]
    assert difference["expected"]["structure"]["record_count"] == expected_count
    assert difference["actual"]["structure"]["record_count"] == actual_count
    assert difference["expected"]["structure"]["top_level_keys"] == [
        "id",
        "status",
    ]
    assert difference["actual"]["structure"]["top_level_keys"] == [
        "id",
        "score",
        "status",
    ]


def test_compare_artifact_trees_exposes_exact_schema_version_change(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    _write_json(
        expected / "summary.json",
        {
            "schema_version": "summary/v1",
            "artifact_schema_versions": {"run_manifest": "run-manifest/v1"},
        },
    )
    _write_json(
        actual / "summary.json",
        {
            "schema_version": "summary/v2",
            "artifact_schema_versions": {"run_manifest": "run-manifest/v2"},
        },
    )

    difference = compare_artifact_trees(expected, actual).to_dict()["differences"][0]

    assert difference["change_reasons"] == [
        "content-changed",
        "schema-version-changed",
    ]
    assert difference["expected"]["structure"]["schema_versions"] == {
        "artifact_schema_versions.run_manifest": ["run-manifest/v1"],
        "schema_version": ["summary/v1"],
    }
    assert difference["actual"]["structure"]["schema_versions"] == {
        "artifact_schema_versions.run_manifest": ["run-manifest/v2"],
        "schema_version": ["summary/v2"],
    }


def test_compare_artifact_trees_exposes_run_manifest_digest_change(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    old_digest = "sha256:" + "0" * 64
    new_digest = "sha256:" + "1" * 64
    base = {
        "input_digest": old_digest,
        "config_digest": old_digest,
        "input_file_digests": {"data/input.jsonl": old_digest},
        "config_file_digests": {"configs/default.yaml": old_digest},
    }
    changed = dict(base, config_digest=new_digest)
    _write_json(expected / "run_manifest.json", base)
    _write_json(actual / "run_manifest.json", changed)

    difference = compare_artifact_trees(expected, actual).to_dict()["differences"][0]

    assert difference["change_reasons"] == [
        "content-changed",
        "run-manifest-digest-changed",
    ]
    assert difference["expected"]["structure"]["run_manifest_digests"] == base
    assert difference["actual"]["structure"]["run_manifest_digests"] == changed


def test_artifact_contract_diff_cli_writes_deterministic_schema_valid_report(
    artifact_roots: tuple[Path, Path], tmp_path: Path
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "summary.json", [{"id": 1}])
    _write_json(actual / "summary.json", [{"id": 1}, {"id": 2}])
    report_path = tmp_path / "artifact-diff.json"
    command = [
        sys.executable,
        str(SCRIPT_PATH),
        "--expected",
        str(expected),
        "--actual",
        str(actual),
        "--json-out",
        str(report_path),
    ]

    first = subprocess.run(command, cwd=REPO_ROOT, text=True, capture_output=True)
    first_bytes = report_path.read_bytes()
    second = subprocess.run(command, cwd=REPO_ROOT, text=True, capture_output=True)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert first.returncode == second.returncode == 1
    assert first.stdout == second.stdout
    assert "[DIFF] 1 artifact contract difference(s)" in first.stdout
    assert "summary.json" in first.stdout
    assert str(expected) not in first.stdout
    assert str(actual) not in first.stdout
    assert first_bytes == report_path.read_bytes()
    Draft202012Validator.check_schema(schema)
    assert list(Draft202012Validator(schema).iter_errors(report)) == []


def test_artifact_contract_diff_cli_returns_zero_for_unchanged_trees(
    artifact_roots: tuple[Path, Path]
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "summary.json", {"count": 1})
    _write_json(actual / "summary.json", {"count": 1})

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--expected",
            str(expected),
            "--actual",
            str(actual),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert "[OK] No artifact contract differences" in result.stdout
