from __future__ import annotations

import argparse
import sys
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
    args = _parser().parse_args(argv)
    try:
        report = compare_artifact_trees(Path(args.expected), Path(args.actual))
    except ArtifactContractDiffError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    _print_summary(report)
    return 1 if report.has_differences else 0


def _print_summary(report: ArtifactContractDiffReport) -> None:
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Explain shallow contract differences between two artifact trees."
    )
    parser.add_argument("--expected", required=True, help="Expected artifact directory")
    parser.add_argument("--actual", required=True, help="Actual artifact directory")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
