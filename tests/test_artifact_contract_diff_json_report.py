from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from telemetry_lab.artifact_contract_diff import (
    ArtifactContractDiffError,
    compare_artifact_trees,
)


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


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _run_cli(
    expected: Path, actual: Path, report_path: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--expected",
            str(expected),
            "--actual",
            str(actual),
            "--json-out",
            str(report_path),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
    )


def _load_cli_script():
    spec = importlib.util.spec_from_file_location(
        "artifact_contract_diff_cli",
        SCRIPT_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_cli_writes_deterministic_schema_valid_report(
    artifact_roots: tuple[Path, Path], tmp_path: Path
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "summary.json", [{"id": 1}])
    _write_json(actual / "summary.json", [{"id": 1}, {"id": 2}])
    report_path = tmp_path / "reports" / "artifact-diff.json"

    first = _run_cli(expected, actual, report_path)
    first_bytes = report_path.read_bytes()
    second = _run_cli(expected, actual, report_path)
    payload = json.loads(report_path.read_text(encoding="utf-8"))

    assert first.returncode == second.returncode == 1
    assert first.stdout == second.stdout
    assert first_bytes == report_path.read_bytes()
    assert first_bytes.endswith(b"\n")
    assert b"\r\n" not in first_bytes
    assert payload["report_schema_version"] == "artifact-contract-diff/v1"
    assert payload["status"] == "changed"
    assert payload["differences"][0]["change_reasons"] == [
        "content-changed",
        "structure-changed",
    ]
    serialized = json.dumps(payload, sort_keys=True)
    assert str(expected) not in serialized
    assert str(actual) not in serialized
    assert "generated_at" not in serialized
    assert list(_validator().iter_errors(payload)) == []


def test_cli_writes_unchanged_report_with_presence_only_binary(
    artifact_roots: tuple[Path, Path], tmp_path: Path
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "summary.json", {"count": 1})
    _write_json(actual / "summary.json", {"count": 1})
    (expected / "plot.png").write_bytes(b"renderer-a")
    (actual / "plot.png").write_bytes(b"renderer-b")
    report_path = tmp_path / "artifact-diff.json"

    result = _run_cli(expected, actual, report_path)
    payload = json.loads(report_path.read_text(encoding="utf-8"))

    assert result.returncode == 0
    assert payload["status"] == "unchanged"
    assert payload["differences"] == []
    assert payload["presence_only_paths"] == ["plot.png"]
    assert payload["summary"]["presence_only_files"] == 1
    assert list(_validator().iter_errors(payload)) == []


@pytest.mark.parametrize("root_name", ["expected", "actual"])
def test_cli_refuses_output_inside_an_input_tree(
    artifact_roots: tuple[Path, Path], root_name: str
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "summary.json", {"count": 1})
    _write_json(actual / "summary.json", {"count": 1})
    root = expected if root_name == "expected" else actual
    report_path = root / "reports" / "artifact-diff.json"
    original = b'{"keep":"artifact"}\n'
    report_path.parent.mkdir()
    report_path.write_bytes(original)

    result = _run_cli(expected, actual, report_path)

    assert result.returncode == 2
    assert "JSON report must be outside both artifact roots" in result.stderr
    assert report_path.read_bytes() == original


def test_json_report_write_is_atomic_on_replace_failure(
    artifact_roots: tuple[Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "summary.json", {"count": 1})
    _write_json(actual / "summary.json", {"count": 2})
    report = compare_artifact_trees(expected, actual)
    report_path = tmp_path / "artifact-diff.json"
    original = b'{"keep":"previous-report"}\n'
    report_path.write_bytes(original)
    cli = _load_cli_script()

    def fail_replace(_source: object, _destination: object) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(cli.os, "replace", fail_replace)

    with pytest.raises(ArtifactContractDiffError, match="cannot write JSON report"):
        cli._write_json_report(report, report_path)

    assert report_path.read_bytes() == original
    assert list(tmp_path.glob(".artifact-diff.json.*.tmp")) == []


def test_cli_preserves_existing_report_when_comparison_fails(
    artifact_roots: tuple[Path, Path], tmp_path: Path
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "summary.json", {"count": 1})
    (actual / "summary.json").write_bytes(b"{\n")
    report_path = tmp_path / "artifact-diff.json"
    original = b'{"keep":"previous-report"}\n'
    report_path.write_bytes(original)

    result = _run_cli(expected, actual, report_path)

    assert result.returncode == 2
    assert "invalid JSON artifact" in result.stderr
    assert str(expected) not in result.stderr
    assert str(actual) not in result.stderr
    assert report_path.read_bytes() == original


def test_cli_does_not_resolve_away_symlink_root_rejection(
    artifact_roots: tuple[Path, Path], tmp_path: Path
) -> None:
    expected, actual = artifact_roots
    linked = tmp_path / "linked-expected"
    try:
        linked.symlink_to(expected, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    report_path = tmp_path / "artifact-diff.json"

    result = _run_cli(linked, actual, report_path)

    assert result.returncode == 2
    assert "non-symlink directory" in result.stderr
    assert not report_path.exists()


def test_report_schema_rejects_cross_field_contradictions(
    artifact_roots: tuple[Path, Path]
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "finding.json", {"status": "old"})
    missing = compare_artifact_trees(expected, actual).to_dict()
    validator = _validator()

    invalid_payloads = [dict(missing, status="unchanged")]
    wrong_missing_reason = json.loads(json.dumps(missing))
    wrong_missing_reason["differences"][0]["change_reasons"] = ["content-changed"]
    invalid_payloads.append(wrong_missing_reason)
    missing_structure = json.loads(json.dumps(missing))
    del missing_structure["differences"][0]["expected"]["structure"]
    invalid_payloads.append(missing_structure)

    _write_json(actual / "finding.json", {"status": "new"})
    changed = compare_artifact_trees(expected, actual).to_dict()
    invalid_payloads.append(dict(changed, differences=[]))
    wrong_changed_reason = json.loads(json.dumps(changed))
    wrong_changed_reason["differences"][0]["change_reasons"] = [
        "missing-from-actual"
    ]
    invalid_payloads.append(wrong_changed_reason)
    changed_binary = json.loads(json.dumps(changed))
    changed_binary["differences"][0]["artifact_kind"] = "binary"
    invalid_payloads.append(changed_binary)
    structured_text = json.loads(json.dumps(changed))
    structured_text["differences"][0]["artifact_kind"] = "text"
    invalid_payloads.append(structured_text)

    for payload in invalid_payloads:
        assert list(validator.iter_errors(payload))


def test_report_payload_is_detached_from_internal_structure(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "summary.json", [{"old": True}])
    _write_json(actual / "summary.json", [{"new": True}])
    report = compare_artifact_trees(expected, actual)

    payload = report.to_dict()
    payload["differences"][0]["expected"]["structure"]["top_level_keys"].append(
        "mutated"
    )

    difference = report.differences[0]
    assert difference.expected is not None
    assert difference.expected.structure is not None
    assert difference.expected.structure["top_level_keys"] == ["old"]
