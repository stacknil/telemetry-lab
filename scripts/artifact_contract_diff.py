from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from telemetry_lab.artifact_contract_diff import (  # noqa: E402
    ArtifactContractDiffError,
    ArtifactContractDiffReport,
    compare_artifact_trees,
)


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        expected_root = _resolve_path(Path(args.expected), "expected artifact root")
        actual_root = _resolve_path(Path(args.actual), "actual artifact root")
        json_out = (
            _resolve_path(Path(args.json_out), "JSON report")
            if args.json_out
            else None
        )
        if json_out is not None:
            _validate_report_destination(json_out, expected_root, actual_root)
        report = compare_artifact_trees(
            expected_root,
            actual_root,
        )
        if json_out is not None:
            _write_json_report(report, json_out)
    except ArtifactContractDiffError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    _print_human_summary(report)
    return 1 if report.has_differences else 0


def _write_json_report(report: ArtifactContractDiffReport, path: Path) -> None:
    temporary_path: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(report.to_dict(), handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    except (OSError, TypeError, ValueError) as exc:
        raise ArtifactContractDiffError("cannot write JSON report") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def _resolve_path(path: Path, label: str) -> Path:
    try:
        return path.resolve(strict=False)
    except OSError as exc:
        raise ArtifactContractDiffError(f"cannot resolve {label}") from exc


def _validate_report_destination(
    report_path: Path,
    expected_root: Path,
    actual_root: Path,
) -> None:
    if _is_within(report_path, expected_root) or _is_within(report_path, actual_root):
        raise ArtifactContractDiffError(
            "JSON report must be outside both artifact roots"
        )


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _print_human_summary(report: ArtifactContractDiffReport) -> None:
    if report.has_differences:
        print(f"[DIFF] {len(report.differences)} artifact contract difference(s)")
        for difference in report.differences:
            reasons = ", ".join(difference.change_reasons)
            print(
                f"- {difference.path}: {difference.status} "
                f"({difference.artifact_kind}; {reasons})"
            )
    else:
        print(
            "[OK] No artifact contract differences "
            f"({report.unchanged_files} comparable file(s))"
        )
    if report.presence_only_paths:
        print(
            f"[INFO] {len(report.presence_only_paths)} binary artifact(s) "
            "checked for presence only"
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Explain shallow contract differences between two artifact trees."
    )
    parser.add_argument("--expected", required=True, help="Expected artifact directory")
    parser.add_argument("--actual", required=True, help="Actual artifact directory")
    parser.add_argument(
        "--json-out",
        help="Optional path for a deterministic artifact-contract-diff/v1 report",
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
