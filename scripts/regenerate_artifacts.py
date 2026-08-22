from __future__ import annotations

import argparse
import io
import os
import shutil
import sys
from uuid import uuid4
from collections.abc import Callable, Iterable, Sequence
from contextlib import contextmanager, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from telemetry_lab.artifact_contract_diff import (  # noqa: E402
    TEXT_ARTIFACT_SUFFIXES,
    normalize_artifact_text_bytes,
)


@dataclass(frozen=True)
class ArtifactSet:
    name: str
    committed_root: Path
    generated_root: Path
    strict_paths: tuple[Path, ...]
    visual_snapshot_paths: tuple[Path, ...] = ()

    @property
    def all_paths(self) -> tuple[Path, ...]:
        return (*self.strict_paths, *self.visual_snapshot_paths)


@dataclass(frozen=True)
class RegenerationJob:
    name: str
    run: Callable[[Path], ArtifactSet]


@dataclass(frozen=True)
class ArtifactDifference:
    job_name: str
    relative_path: Path
    committed_path: Path
    generated_path: Path
    reason: str


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    work_root = _resolve_repo_path(args.work_dir)
    jobs = build_jobs()

    try:
        differences = run_regeneration_check(
            jobs,
            work_root=work_root,
            check=bool(args.check),
        )
    finally:
        if args.clean:
            _clean_work_root(work_root)

    if differences:
        print(f"[FAIL] {len(differences)} artifact mismatch(es) found.")
        for difference in differences:
            print(
                f"- {difference.job_name}: {difference.relative_path.as_posix()} "
                f"({difference.reason})"
            )
            print(f"  committed: {_display_path(difference.committed_path)}")
            print(f"  generated: {_display_path(difference.generated_path)}")
        print("Run `python scripts/regenerate_artifacts.py` to update committed artifacts.")
        return 1

    return 0


def run_regeneration_check(
    jobs: Sequence[RegenerationJob],
    *,
    work_root: Path,
    check: bool,
) -> list[ArtifactDifference]:
    _prepare_work_root(work_root)
    run_root = work_root / f"run-{uuid4().hex}"
    run_root.mkdir(parents=True)
    differences: list[ArtifactDifference] = []
    checked_count = 0
    visual_count = 0

    for job in jobs:
        job_root = run_root / _slug(job.name)
        job_root.mkdir(parents=True)

        artifact_set = job.run(job_root)
        checked_count += len(artifact_set.strict_paths)
        visual_count += len(artifact_set.visual_snapshot_paths)
        if check:
            differences.extend(compare_artifact_set(job.name, artifact_set))
        else:
            copy_generated_artifacts(artifact_set)
        print(f"[OK] {job.name}: {len(artifact_set.all_paths)} artifact(s) generated")

    if not differences and check:
        print(f"[OK] {checked_count} committed artifact(s) match regenerated output")
        if visual_count:
            print(
                f"[OK] {visual_count} visual snapshot artifact(s) regenerated "
                "without byte comparison"
            )
    elif not differences:
        print(
            f"[OK] {checked_count + visual_count} committed artifact(s) updated "
            "from regenerated output"
        )

    return differences


def compare_artifact_set(
    job_name: str,
    artifact_set: ArtifactSet,
) -> list[ArtifactDifference]:
    differences: list[ArtifactDifference] = []
    for relative_path in artifact_set.strict_paths:
        committed_path = artifact_set.committed_root / relative_path
        generated_path = artifact_set.generated_root / relative_path

        reason: str | None = None
        if not committed_path.is_file():
            reason = "committed artifact is missing"
        elif not generated_path.is_file():
            reason = "regenerated artifact is missing"
        elif not artifacts_match(committed_path, generated_path):
            reason = "content differs"

        if reason is not None:
            differences.append(
                ArtifactDifference(
                    job_name=job_name,
                    relative_path=relative_path,
                    committed_path=committed_path,
                    generated_path=generated_path,
                    reason=reason,
                )
            )

    for relative_path in artifact_set.visual_snapshot_paths:
        committed_path = artifact_set.committed_root / relative_path
        generated_path = artifact_set.generated_root / relative_path

        reason: str | None = None
        if not committed_path.is_file():
            reason = "committed visual artifact is missing"
        elif not generated_path.is_file():
            reason = "regenerated visual artifact is missing"

        if reason is not None:
            differences.append(
                ArtifactDifference(
                    job_name=job_name,
                    relative_path=relative_path,
                    committed_path=committed_path,
                    generated_path=generated_path,
                    reason=reason,
                )
            )
    return differences


def artifacts_match(committed_path: Path, generated_path: Path) -> bool:
    if committed_path.suffix.lower() in TEXT_ARTIFACT_SUFFIXES:
        return _normalized_text_bytes(committed_path) == _normalized_text_bytes(
            generated_path
        )
    return committed_path.read_bytes() == generated_path.read_bytes()


def copy_generated_artifacts(artifact_set: ArtifactSet) -> None:
    for relative_path in artifact_set.all_paths:
        committed_path = artifact_set.committed_root / relative_path
        generated_path = artifact_set.generated_root / relative_path
        committed_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(generated_path, committed_path)


def build_jobs() -> list[RegenerationJob]:
    return [
        RegenerationJob(
            name="telemetry-lab window default sample",
            run=lambda job_root: _run_window_pipeline_job(
                job_root,
                config_path=REPO_ROOT / "configs" / "default.yaml",
                committed_root=REPO_ROOT / "data" / "processed",
            ),
        ),
        RegenerationJob(
            name="telemetry-lab window richer sample",
            run=lambda job_root: _run_window_pipeline_job(
                job_root,
                config_path=REPO_ROOT / "configs" / "richer_sample.yaml",
                committed_root=REPO_ROOT / "data" / "processed" / "richer_sample",
            ),
        ),
        RegenerationJob(
            name="ai-assisted-detection-demo",
            run=lambda job_root: _run_demo_job(
                job_root,
                committed_root=REPO_ROOT / "demos" / "ai-assisted-detection-demo" / "artifacts",
                runner=_run_ai_demo,
                relative_paths=(
                    "rule_hits.json",
                    "case_bundles.json",
                    "case_summaries.json",
                    "case_report.md",
                    "audit_traces.jsonl",
                    "run_manifest.json",
                ),
            ),
        ),
        RegenerationJob(
            name="rule-evaluation-and-dedup-demo",
            run=lambda job_root: _run_demo_job(
                job_root,
                committed_root=REPO_ROOT / "demos" / "rule-evaluation-and-dedup-demo" / "artifacts",
                runner=_run_rule_dedup_demo,
                relative_paths=(
                    "rule_hits_before_dedup.json",
                    "rule_hits_after_dedup.json",
                    "dedup_explanations.json",
                    "dedup_report.md",
                    "run_manifest.json",
                ),
            ),
        ),
        RegenerationJob(
            name="config-change-investigation-demo",
            run=lambda job_root: _run_demo_job(
                job_root,
                committed_root=REPO_ROOT / "demos" / "config-change-investigation-demo" / "artifacts",
                runner=_run_config_change_demo,
                relative_paths=(
                    "change_events_normalized.json",
                    "investigation_hits.json",
                    "investigation_summary.json",
                    "investigation_report.md",
                    "run_manifest.json",
                ),
            ),
        ),
        RegenerationJob(
            name="cloud-iam-change-investigation-demo",
            run=lambda job_root: _run_demo_job(
                job_root,
                committed_root=REPO_ROOT / "demos" / "cloud-iam-change-investigation-demo" / "artifacts",
                runner=_run_cloud_iam_demo,
                relative_paths=(
                    "normalized_cloudtrail_events.json",
                    "investigation_signals.json",
                    "investigation_summary.json",
                    "investigation_report.md",
                    "run_manifest.json",
                ),
            ),
        ),
    ]


def _run_window_pipeline_job(
    job_root: Path,
    *,
    config_path: Path,
    committed_root: Path,
) -> ArtifactSet:
    from telemetry_lab.cli import run_command
    from telemetry_lab.io import load_config

    config = load_config(config_path)
    generated_repo = job_root / "repo"
    generated_config_dir = generated_repo / "configs"
    generated_config_dir.mkdir(parents=True)
    shutil.copytree(REPO_ROOT / "data" / "raw", generated_repo / "data" / "raw")

    generated_config_path = generated_config_dir / config_path.name
    shutil.copyfile(config_path, generated_config_path)
    with _pushd(generated_repo), redirect_stdout(io.StringIO()):
        run_command(SimpleNamespace(config=str(generated_config_path)))

    generated_root = generated_repo / str(config["output_dir"])

    return ArtifactSet(
        name=config_path.stem,
        committed_root=committed_root,
        generated_root=generated_root,
        strict_paths=(
            Path("features.csv"),
            Path("alerts.csv"),
            Path("summary.json"),
            Path("run_manifest.json"),
        ),
        visual_snapshot_paths=(
            Path("event_count_timeline.png"),
            Path("error_rate_timeline.png"),
            Path("alerts_timeline.png"),
        ),
    )


def _run_demo_job(
    job_root: Path,
    *,
    committed_root: Path,
    runner: Callable[[Path], Any],
    relative_paths: Iterable[str],
) -> ArtifactSet:
    generated_root = job_root / "artifacts"
    runner(generated_root)
    return ArtifactSet(
        name=committed_root.parent.name,
        committed_root=committed_root,
        generated_root=generated_root,
        strict_paths=tuple(Path(path) for path in relative_paths),
    )


def _run_ai_demo(artifacts_dir: Path) -> None:
    from telemetry_lab.ai_assisted_detection_demo import default_demo_root, run_demo

    run_demo(demo_root=default_demo_root(), artifacts_dir=artifacts_dir)


def _run_rule_dedup_demo(artifacts_dir: Path) -> None:
    from telemetry_lab.rule_evaluation_and_dedup_demo import (
        default_demo_root,
        run_demo,
    )

    run_demo(demo_root=default_demo_root(), artifacts_dir=artifacts_dir)


def _run_config_change_demo(artifacts_dir: Path) -> None:
    from telemetry_lab.config_change_investigation_demo import (
        default_demo_root,
        run_demo,
    )

    run_demo(demo_root=default_demo_root(), artifacts_dir=artifacts_dir)


def _run_cloud_iam_demo(artifacts_dir: Path) -> None:
    from telemetry_lab.cloud_iam_change_investigation_demo import (
        default_demo_root,
        run_demo,
    )

    run_demo(demo_root=default_demo_root(), artifacts_dir=artifacts_dir)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Regenerate committed demo artifacts and compare them with pipeline output.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare regenerated artifacts with committed artifacts without modifying files.",
    )
    parser.add_argument(
        "--work-dir",
        default=".artifact-regeneration-tmp",
        help="Repository-relative directory used for regenerated artifacts.",
    )
    parser.add_argument(
        "--no-clean",
        dest="clean",
        action="store_false",
        help="Keep the temporary regeneration directory for inspection.",
    )
    parser.set_defaults(clean=True)
    return parser


def _resolve_repo_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return (REPO_ROOT / path).resolve()


def _prepare_work_root(work_root: Path) -> None:
    work_root.mkdir(parents=True, exist_ok=True)
    resolved = work_root.resolve()
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ValueError(f"work-dir must stay inside the repository: {resolved}") from exc


def _clean_work_root(work_root: Path) -> None:
    if not work_root.exists():
        return
    resolved = work_root.resolve()
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ValueError(f"refusing to clean work-dir outside repository: {resolved}") from exc
    try:
        shutil.rmtree(resolved)
    except OSError as exc:
        print(
            f"[WARN] Could not remove temporary artifact directory "
            f"{_display_path(resolved)}: {exc}",
            file=sys.stderr,
        )


def _slug(value: str) -> str:
    return "".join(char if char.isalnum() else "-" for char in value.lower()).strip("-")


def _normalized_text_bytes(path: Path) -> bytes:
    return normalize_artifact_text_bytes(path.read_bytes())


@contextmanager
def _pushd(path: Path):
    original = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(original)


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.resolve().as_posix()


if __name__ == "__main__":
    raise SystemExit(main())
