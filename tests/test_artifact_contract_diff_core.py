from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from telemetry_lab.artifact_contract_diff import (
    ArtifactContractDiffError,
    ArtifactContractDiffReport,
    ArtifactDifference,
    ArtifactSnapshot,
    compare_artifact_trees,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "artifact_contract_diff.py"


@pytest.fixture
def artifact_roots(tmp_path: Path) -> tuple[Path, Path]:
    expected = tmp_path / "expected"
    actual = tmp_path / "actual"
    expected.mkdir()
    actual.mkdir()
    return expected, actual


def _write_json(path: Path, value: object, *, newline: str = "\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, sort_keys=True) + newline).encode())


def _run_cli(expected: Path, actual: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
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


def test_compare_normalizes_text_and_treats_binary_as_presence_only(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    (expected / "report.md").write_bytes(b"same\r\nline\r")
    (actual / "report.md").write_bytes(b"same\nline\n")
    _write_json(expected / "summary.json", {"count": 1}, newline="\r\n")
    _write_json(actual / "summary.json", {"count": 1})
    (expected / "plot.png").write_bytes(b"renderer-a")
    (actual / "plot.png").write_bytes(b"renderer-b")

    report = compare_artifact_trees(expected, actual)

    assert not report.has_differences
    assert report.unchanged_files == 2
    assert report.presence_only_paths == ("plot.png",)
    assert report.expected_files == report.actual_files == 3


def test_compare_reports_missing_and_extra_in_stable_order(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "z-common.json", {"same": True})
    _write_json(actual / "z-common.json", {"same": True})
    _write_json(expected / "nested" / "a-missing.json", {"old": True})
    _write_json(actual / "b-extra.json", {"new": True})

    report = compare_artifact_trees(expected, actual)

    assert [difference.path for difference in report.differences] == [
        "b-extra.json",
        "nested/a-missing.json",
    ]
    assert [difference.status for difference in report.differences] == [
        "extra",
        "missing",
    ]
    assert report.unchanged_files == 1
    assert report.missing_files == report.extra_files == 1


def test_difference_constructor_rejects_contradictory_state() -> None:
    snapshot = ArtifactSnapshot("sha256:" + "0" * 64, 1)

    with pytest.raises(ArtifactContractDiffError, match="missing difference"):
        ArtifactDifference(
            path="artifact.json",
            status="missing",
            artifact_kind="json",
            change_reasons=("content-changed",),
            expected=snapshot,
        )

    with pytest.raises(ArtifactContractDiffError, match="changed difference"):
        ArtifactDifference(
            path="artifact.json",
            status="changed",
            artifact_kind="json",
            change_reasons=("content-changed", "extra-in-actual"),
            expected=snapshot,
            actual=snapshot,
        )


def test_report_rejects_difference_presence_overlap() -> None:
    snapshot = ArtifactSnapshot("sha256:" + "0" * 64, 1)
    difference = ArtifactDifference(
        path="artifact.json",
        status="missing",
        artifact_kind="json",
        change_reasons=("missing-from-actual",),
        expected=snapshot,
    )

    with pytest.raises(ArtifactContractDiffError, match="paths overlap"):
        ArtifactContractDiffReport(
            expected_files=2,
            actual_files=1,
            unchanged_files=0,
            missing_files=1,
            extra_files=0,
            changed_files=0,
            differences=(difference,),
            presence_only_paths=("artifact.json",),
        )


def test_compare_rejects_invalid_utf8_text(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    (expected / "summary.json").write_bytes(b"valid\n")
    (actual / "summary.json").write_bytes(b"invalid:\xff\n")

    with pytest.raises(ArtifactContractDiffError, match="not valid UTF-8"):
        compare_artifact_trees(expected, actual)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX mkfifo")
def test_compare_rejects_special_files(
    artifact_roots: tuple[Path, Path],
) -> None:
    expected, actual = artifact_roots
    os.mkfifo(expected / "blocked.json")

    with pytest.raises(ArtifactContractDiffError, match="non-regular artifact"):
        compare_artifact_trees(expected, actual)


def test_compare_rejects_symlink_root(
    artifact_roots: tuple[Path, Path], tmp_path: Path
) -> None:
    expected, actual = artifact_roots
    linked = tmp_path / "linked-expected"
    try:
        linked.symlink_to(expected, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(ArtifactContractDiffError, match="non-symlink directory"):
        compare_artifact_trees(linked, actual)


def test_human_cli_distinguishes_unchanged_changed_and_invalid(
    artifact_roots: tuple[Path, Path], tmp_path: Path
) -> None:
    expected, actual = artifact_roots
    _write_json(expected / "summary.json", {"count": 1})
    _write_json(actual / "summary.json", {"count": 1})

    unchanged = _run_cli(expected, actual)
    _write_json(actual / "summary.json", {"count": 2})
    changed = _run_cli(expected, actual)
    invalid = _run_cli(expected, tmp_path / "missing")

    assert unchanged.returncode == 0
    assert "[OK] No artifact contract differences" in unchanged.stdout
    assert changed.returncode == 1
    assert "summary.json: changed" in changed.stdout
    assert invalid.returncode == 2
    assert "[ERROR]" in invalid.stderr
    assert str(expected) not in changed.stdout
