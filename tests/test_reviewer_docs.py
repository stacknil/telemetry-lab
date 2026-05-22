from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

REVIEWER_DEMO_MATRIX = [
    (
        "How are raw events converted to alert features?",
        "telemetry-window-demo",
        [
            "data/processed/features.csv",
            "data/processed/alerts.csv",
            "data/processed/summary.json",
        ],
    ),
    (
        "How is AI constrained?",
        "ai-assisted-detection-demo",
        [
            "demos/ai-assisted-detection-demo/artifacts/case_summaries.json",
            "demos/ai-assisted-detection-demo/artifacts/audit_traces.jsonl",
            "demos/ai-assisted-detection-demo/README.md",
        ],
    ),
    (
        "How are duplicate alerts reduced?",
        "rule-evaluation-and-dedup-demo",
        [
            "demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_before_dedup.json",
            "demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_after_dedup.json",
            "demos/rule-evaluation-and-dedup-demo/artifacts/dedup_explanations.json",
        ],
    ),
    (
        "How are risky config changes investigated?",
        "config-change-investigation-demo",
        [
            "demos/config-change-investigation-demo/artifacts/investigation_hits.json",
            "demos/config-change-investigation-demo/artifacts/investigation_report.md",
        ],
    ),
]


def _read_repo_file(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_reviewer_path_keeps_detection_lab_positioning() -> None:
    reviewer_path = _read_repo_file("docs/reviewer-path.md")
    normalized = reviewer_path.lower()

    assert "controlled detection workflow portfolio" in reviewer_path
    assert "not a siem" in normalized
    assert "not a dashboard" in normalized
    assert "not an unfinished monitoring platform" in normalized
    assert "local and file-based" in normalized


def test_reviewer_path_matrix_references_committed_artifacts() -> None:
    reviewer_path = _read_repo_file("docs/reviewer-path.md")

    for question, demo_name, artifact_paths in REVIEWER_DEMO_MATRIX:
        assert f"| {question} | `{demo_name}` |" in reviewer_path
        for artifact_path in artifact_paths:
            assert f"`{artifact_path}`" in reviewer_path
            assert (REPO_ROOT / artifact_path).is_file(), artifact_path


def test_readme_links_reviewer_path_and_uses_lab_framing() -> None:
    readme = _read_repo_file("README.md")

    assert "A local, file-based detection workflow lab" in readme
    assert "not a SIEM, dashboard, or monitoring platform" in readme
    assert "[`docs/reviewer-path.md`](docs/reviewer-path.md)" in readme
