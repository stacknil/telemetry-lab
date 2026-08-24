from __future__ import annotations

import json
from pathlib import Path

import pytest

from telemetry_lab import artifact_contract_diff as artifact_diff
from telemetry_lab.artifact_contract_diff import (
    ArtifactContractDiffError,
    compare_artifact_trees,
)


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


@pytest.mark.parametrize(
    ("name", "old", "new", "old_count", "new_count"),
    [
        (
            "records.json",
            b'[{"id":1,"status":"old"}]\n',
            b'[{"id":1,"status":"old"},{"id":2,"score":7}]\n',
            1,
            2,
        ),
        (
            "records.jsonl",
            b'{"id":1,"status":"old"}\n',
            b'{"id":1,"status":"old"}\n\n{"id":2,"score":7}\n',
            1,
            2,
        ),
    ],
)
def test_compare_summarizes_changed_structured_records(
    artifact_roots: tuple[Path, Path],
    name: str,
    old: bytes,
    new: bytes,
    old_count: int,
    new_count: int,
) -> None:
    expected, actual = artifact_roots
    (expected / name).write_bytes(old)
    (actual / name).write_bytes(new)

    difference = compare_artifact_trees(expected, actual).differences[0]

    assert difference.change_reasons == ("content-changed", "structure-changed")
    assert difference.expected is not None
    assert difference.actual is not None
    assert difference.expected.structure is not None
    assert difference.actual.structure is not None
    assert difference.expected.structure["record_count"] == old_count
    assert difference.actual.structure["record_count"] == new_count
    assert difference.actual.structure["top_level_keys"] == ["id", "score", "status"]


def test_compare_exposes_schema_and_run_manifest_digest_changes(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    old_digest = "sha256:" + "0" * 64
    new_digest = "sha256:" + "1" * 64
    _write_json(
        expected / "run_manifest.json",
        {
            "schema_version": "summary/v1",
            "artifact_schema_versions": {"run_manifest": "run-manifest/v1"},
            "input_digest": old_digest,
            "input_file_digests": {"data/input.jsonl": old_digest},
        },
    )
    _write_json(
        actual / "run_manifest.json",
        {
            "schema_version": "summary/v2",
            "artifact_schema_versions": {"run_manifest": "run-manifest/v2"},
            "input_digest": new_digest,
            "input_file_digests": {"data/input.jsonl": new_digest},
        },
    )

    difference = compare_artifact_trees(expected, actual).differences[0]

    assert difference.change_reasons == (
        "content-changed",
        "schema-version-changed",
        "run-manifest-digest-changed",
    )
    assert difference.expected is not None
    assert difference.expected.structure == {
        "container": "object",
        "record_count": 1,
        "top_level_keys": [
            "artifact_schema_versions",
            "input_digest",
            "input_file_digests",
            "schema_version",
        ],
        "schema_versions": {
            "artifact_schema_versions.run_manifest": ["run-manifest/v1"],
            "schema_version": ["summary/v1"],
        },
        "run_manifest_digests": {
            "input_digest": old_digest,
            "input_file_digests": {"data/input.jsonl": old_digest},
        },
    }


@pytest.mark.parametrize(
    "invalid_digests",
    [
        {"input_digest": "not-a-sha256"},
        {"input_file_digests": ["not", "a", "mapping"]},
        {"config_file_digests": {"../outside": "sha256:" + "0" * 64}},
        {"input_file_digests": {"/absolute/input": "sha256:" + "0" * 64}},
    ],
)
def test_compare_rejects_invalid_run_manifest_digest_fields(
    artifact_roots: tuple[Path, Path], invalid_digests: object
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "run_manifest.json", {"input_digest": "sha256:" + "0" * 64})
    _write_json(actual / "run_manifest.json", invalid_digests)

    with pytest.raises(ArtifactContractDiffError, match="run-manifest digest"):
        compare_artifact_trees(expected, actual)


def test_compare_does_not_parse_identical_json(
    artifact_roots: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "same.json", {"count": 1})
    _write_json(actual / "same.json", {"count": 1})

    def fail_if_parsed(_text: str) -> object:
        raise AssertionError("identical JSON should not be parsed")

    monkeypatch.setattr(artifact_diff.json, "loads", fail_if_parsed)

    assert not compare_artifact_trees(expected, actual).has_differences


def test_structural_summary_is_order_independent(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    (expected / "summary.json").write_bytes(b'{"first":1,"second":2}\n')
    (actual / "summary.json").write_bytes(b'{"second":2,"first":1}\n')

    difference = compare_artifact_trees(expected, actual).differences[0]

    assert difference.change_reasons == ("content-changed",)
    assert difference.expected is not None
    assert difference.actual is not None
    assert difference.expected.structure == difference.actual.structure


def test_missing_and_extra_structured_snapshots_keep_summaries(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "missing.json", [{"expected": True}])
    (actual / "extra.jsonl").write_bytes(b'{"actual":true}\n')

    extra, missing = compare_artifact_trees(expected, actual).differences

    assert extra.actual is not None
    assert extra.actual.structure == {
        "container": "jsonl",
        "record_count": 1,
        "top_level_keys": ["actual"],
    }
    assert missing.expected is not None
    assert missing.expected.structure == {
        "container": "array",
        "record_count": 1,
        "top_level_keys": ["expected"],
    }


@pytest.mark.parametrize(
    ("name", "invalid", "message"),
    [
        ("summary.json", b"{\n", "invalid JSON artifact"),
        ("records.jsonl", b"{\n", "invalid JSONL artifact"),
    ],
)
def test_compare_rejects_changed_invalid_structured_artifact(
    artifact_roots: tuple[Path, Path], name: str, invalid: bytes, message: str
) -> None:
    expected, actual = artifact_roots
    (expected / name).write_bytes(b'{}\n')
    (actual / name).write_bytes(invalid)

    with pytest.raises(ArtifactContractDiffError, match=message):
        compare_artifact_trees(expected, actual)


def test_compare_rejects_unsafe_schema_marker(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "summary.json", {"schema_version": "summary/v1"})
    _write_json(actual / "summary.json", {"schema_version": "file:///local/schema"})

    with pytest.raises(ArtifactContractDiffError, match="unsafe schema marker"):
        compare_artifact_trees(expected, actual)


def test_compare_bounds_changed_structured_artifacts(
    artifact_roots: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "summary.json", {"value": "old"})
    _write_json(actual / "summary.json", {"value": "new"})
    monkeypatch.setattr(artifact_diff, "MAX_STRUCTURED_BYTES", 8)

    with pytest.raises(ArtifactContractDiffError, match="summary limit"):
        compare_artifact_trees(expected, actual)
