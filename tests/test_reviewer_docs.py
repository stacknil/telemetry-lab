from __future__ import annotations

import tomllib
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
    (
        "How are IAM changes investigated from CloudTrail-like events?",
        "cloud-iam-change-investigation-demo",
        [
            "demos/cloud-iam-change-investigation-demo/artifacts/investigation_signals.json",
            "demos/cloud-iam-change-investigation-demo/artifacts/investigation_report.md",
        ],
    ),
]

STABLE_REVIEWER_ARTIFACTS = [
    "data/processed/features.csv",
    "data/processed/alerts.csv",
    "data/processed/summary.json",
    "data/processed/event_count_timeline.png",
    "data/processed/error_rate_timeline.png",
    "data/processed/alerts_timeline.png",
    "data/processed/richer_sample/features.csv",
    "data/processed/richer_sample/alerts.csv",
    "data/processed/richer_sample/summary.json",
    "data/processed/richer_sample/event_count_timeline.png",
    "data/processed/richer_sample/error_rate_timeline.png",
    "data/processed/richer_sample/alerts_timeline.png",
    "demos/ai-assisted-detection-demo/artifacts/rule_hits.json",
    "demos/ai-assisted-detection-demo/artifacts/case_bundles.json",
    "demos/ai-assisted-detection-demo/artifacts/case_summaries.json",
    "demos/ai-assisted-detection-demo/artifacts/case_report.md",
    "demos/ai-assisted-detection-demo/artifacts/audit_traces.jsonl",
    "demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_before_dedup.json",
    "demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_after_dedup.json",
    "demos/rule-evaluation-and-dedup-demo/artifacts/dedup_explanations.json",
    "demos/rule-evaluation-and-dedup-demo/artifacts/dedup_report.md",
    "demos/config-change-investigation-demo/artifacts/change_events_normalized.json",
    "demos/config-change-investigation-demo/artifacts/investigation_hits.json",
    "demos/config-change-investigation-demo/artifacts/investigation_summary.json",
    "demos/config-change-investigation-demo/artifacts/investigation_report.md",
    "demos/cloud-iam-change-investigation-demo/artifacts/normalized_cloudtrail_events.json",
    "demos/cloud-iam-change-investigation-demo/artifacts/investigation_signals.json",
    "demos/cloud-iam-change-investigation-demo/artifacts/investigation_summary.json",
    "demos/cloud-iam-change-investigation-demo/artifacts/investigation_report.md",
]


def _read_repo_file(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def _read_pyproject() -> dict[str, object]:
    return tomllib.loads(_read_repo_file("pyproject.toml"))


def test_reviewer_path_keeps_detection_lab_positioning() -> None:
    reviewer_path = _read_repo_file("docs/reviewer-path.md")
    reviewer_brief = _read_repo_file("docs/reviewer-brief.md")
    normalized = reviewer_path.lower()

    assert "controlled detection workflow portfolio" in reviewer_path
    assert "not a siem" in normalized
    assert "not a dashboard" in normalized
    assert "not an unfinished monitoring platform" in normalized
    assert "local and file-based" in normalized
    assert "small-scope detection workflow demos" in reviewer_brief


def test_reviewer_path_matrix_references_committed_artifacts() -> None:
    reviewer_path = _read_repo_file("docs/reviewer-path.md")

    for question, demo_name, artifact_paths in REVIEWER_DEMO_MATRIX:
        assert f"| {question} | `{demo_name}` |" in reviewer_path
        for artifact_path in artifact_paths:
            assert f"`{artifact_path}`" in reviewer_path
            assert (REPO_ROOT / artifact_path).is_file(), artifact_path


def test_readme_links_reviewer_path_and_uses_lab_framing() -> None:
    readme = _read_repo_file("README.md")
    normalized = readme.lower()

    assert "A local, file-based detection workflow lab" in readme
    assert "local, reviewer-oriented detection workflow lab" in readme
    assert "not a SIEM, dashboard, or monitoring platform" in readme
    assert "## Reviewer Start" in readme
    assert "scope, value, evidence, and boundaries" in readme
    assert "choose the right demo by review question" in readme
    assert "demo matrix, artifact contract, and v1 readiness gate" in readme
    assert "current route, supporting docs, and historical release evidence" in readme
    assert "[`docs/README.md`](docs/README.md)" in readme
    assert "[`docs/reviewer-pack.md`](docs/reviewer-pack.md)" in readme
    assert "[`docs/reviewer-brief.md`](docs/reviewer-brief.md)" in readme
    assert "[`docs/reviewer-path.md`](docs/reviewer-path.md)" in readme
    assert "[`docs/architecture.md`](docs/architecture.md)" in readme
    assert "portfolio prototype" not in normalized
    assert "mvp only" not in normalized


def test_docs_index_separates_current_route_from_history() -> None:
    docs_index = _read_repo_file("docs/README.md")
    normalized = docs_index.lower()

    assert "Current reviewer route" in docs_index
    assert "Supporting docs" in docs_index
    assert "Historical release evidence" in docs_index
    assert "Use the current reviewer route above" in docs_index
    assert "not a siem, dashboard, or production monitoring platform" in normalized

    for current_doc in [
        "reviewer-pack.md",
        "reviewer-path.md",
        "reviewer-brief.md",
        "evidence-pipeline-contract.md",
        "reviewer-artifact-diff.md",
        "vocabulary.md",
        "architecture.md",
        "roadmap.md",
    ]:
        assert f"({current_doc})" in docs_index

    for historical_doc in [
        "release-v0.4.0.md",
        "reviewer-pack-v0.4.0/MANIFEST.md",
        "reviewer-pack-v0.6.0/MANIFEST.md",
    ]:
        assert f"({historical_doc})" in docs_index


def test_package_metadata_uses_detection_lab_framing() -> None:
    pyproject = _read_pyproject()
    description = str(pyproject["project"]["description"])

    assert description == (
        "A local, file-based detection workflow lab for "
        "reviewer-verifiable telemetry and detection demos."
    )
    assert "small prototype" not in description.lower()
    assert "monitoring platform" not in description.lower()


def test_top_level_reviewer_pack_covers_matrix_and_artifact_contract() -> None:
    reviewer_pack = _read_repo_file("docs/reviewer-pack.md")

    assert "top-level reviewer pack" in reviewer_pack
    assert "Artifact Naming Contract" in reviewer_pack
    assert "[`docs/README.md`](README.md)" in reviewer_pack
    assert "[`docs/reviewer-path.md`](reviewer-path.md)" in reviewer_pack
    assert "[`docs/reviewer-artifact-diff.md`](reviewer-artifact-diff.md)" in reviewer_pack
    assert "[`docs/vocabulary.md`](vocabulary.md)" in reviewer_pack
    assert "[`docs/architecture.md`](architecture.md)" in reviewer_pack
    assert "[`docs/roadmap.md`](roadmap.md)" in reviewer_pack
    assert "current route, supporting docs, and historical release evidence" in reviewer_pack

    for question, demo_name, artifact_paths in REVIEWER_DEMO_MATRIX:
        assert question in reviewer_pack
        assert f"`{demo_name}`" in reviewer_pack
        for artifact_path in artifact_paths:
            assert f"`{artifact_path}`" in reviewer_pack


def test_reviewer_pack_freezes_stable_artifact_names() -> None:
    reviewer_pack = _read_repo_file("docs/reviewer-pack.md")

    assert "Stable Reviewer-Visible Artifacts" in reviewer_pack
    for artifact_path in STABLE_REVIEWER_ARTIFACTS:
        assert f"`{artifact_path}`" in reviewer_pack
        assert (REPO_ROOT / artifact_path).is_file(), artifact_path


def test_reviewer_pack_defines_v1_readiness_gate() -> None:
    reviewer_pack = _read_repo_file("docs/reviewer-pack.md")
    roadmap = _read_repo_file("docs/roadmap.md")
    readme = _read_repo_file("README.md")

    assert "## v1 Readiness Gate" in reviewer_pack
    assert "five-demo matrix stable" in reviewer_pack
    assert "reviewer-visible artifact names stable" in reviewer_pack
    assert "package metadata, and repository metadata" in reviewer_pack
    assert "Regenerate and inspect committed artifacts" in reviewer_pack
    assert "Run `pytest`" in reviewer_pack
    assert "reviewer-facing artifact diff" in reviewer_pack
    assert "added fields, removed fields, semantic changes, and compatibility notes" in reviewer_pack
    assert "Do not add SIEM, dashboard, alert routing" in reviewer_pack
    assert "[`docs/reviewer-pack.md`](reviewer-pack.md#v1-readiness-gate)" in roadmap
    assert "[`v1 readiness gate`](docs/reviewer-pack.md#v1-readiness-gate)" in readme


def test_current_docs_use_v1_contract_stabilization_language() -> None:
    current_docs = {
        "README.md": _read_repo_file("README.md"),
        "docs/README.md": _read_repo_file("docs/README.md"),
        "docs/reviewer-pack.md": _read_repo_file("docs/reviewer-pack.md"),
        "docs/reviewer-brief.md": _read_repo_file("docs/reviewer-brief.md"),
        "docs/architecture.md": _read_repo_file("docs/architecture.md"),
        "docs/roadmap.md": _read_repo_file("docs/roadmap.md"),
    }

    assert "Demo expansion is closed." in current_docs["docs/roadmap.md"]
    assert "Next phase: v1 reviewer contract stabilization." in current_docs["docs/roadmap.md"]
    assert "## v1 Reviewer Contract Stabilization" in current_docs["README.md"]

    for path, text in current_docs.items():
        assert "v1 reviewer contract stabilization" in text, path
        assert "v0.7 / v1.0" not in text, path


def test_vocabulary_defines_cross_demo_terms() -> None:
    vocabulary = _read_repo_file("docs/vocabulary.md")
    docs_index = _read_repo_file("docs/README.md")
    readme = _read_repo_file("README.md")
    evidence_contract = _read_repo_file("docs/evidence-pipeline-contract.md")
    roadmap = _read_repo_file("docs/roadmap.md")

    assert "local evidence workflow vocabulary" in vocabulary
    assert "not a SIEM object model" in vocabulary
    assert "[`docs/event-time-model.md`](event-time-model.md)" in vocabulary
    assert "## Bounded Correlation" in vocabulary
    assert "fixed time window" in vocabulary
    assert "fixed entity or scope key" in vocabulary
    assert "fixed event family" in vocabulary
    assert "does not perform global attribution across hosts, accounts, sources" in vocabulary

    for term in [
        "event",
        "signal",
        "hit",
        "finding",
        "case_bundle",
        "summary",
        "report",
        "audit_trace",
    ]:
        assert f"`{term}`" in vocabulary
        assert f"`{term}`" in evidence_contract

    for text in [docs_index, readme]:
        assert "vocabulary.md" in text
        assert "cross-demo" in text

    assert "[`docs/vocabulary.md`](vocabulary.md)" in roadmap
    assert "Keep cross-demo vocabulary stable" in roadmap


def test_reviewer_artifact_diff_contract_covers_release_changes() -> None:
    artifact_diff = _read_repo_file("docs/reviewer-artifact-diff.md")
    docs_index = _read_repo_file("docs/README.md")
    readme = _read_repo_file("README.md")
    evidence_contract = _read_repo_file("docs/evidence-pipeline-contract.md")
    roadmap = _read_repo_file("docs/roadmap.md")

    assert "Every release must include a concise artifact diff" in artifact_diff
    assert "`no-artifact-change`" in artifact_diff
    assert "## Required Release Diff Sections" in artifact_diff
    assert "## Compatibility Labels" in artifact_diff
    assert "## Template" in artifact_diff
    assert "[`docs/reviewer-pack.md`](reviewer-pack.md)" in artifact_diff
    assert "[`docs/evidence-pipeline-contract.md`](evidence-pipeline-contract.md)" in artifact_diff

    for required_term in [
        "Added fields",
        "Removed fields",
        "Semantic changes",
        "Compatibility notes",
        "no-artifact-change",
        "additive-compatible",
        "semantic-change",
        "breaking-artifact-change",
    ]:
        assert required_term in artifact_diff

    for text in [docs_index, readme, evidence_contract, roadmap]:
        assert "reviewer-artifact-diff.md" in text

    assert "Include reviewer-facing artifact diffs in every release" in roadmap


def test_bounded_correlation_boundaries_are_documented() -> None:
    architecture = _read_repo_file("docs/architecture.md")
    reviewer_pack = _read_repo_file("docs/reviewer-pack.md")
    config_demo = _read_repo_file("demos/config-change-investigation-demo/README.md")
    cloud_iam_demo = _read_repo_file(
        "demos/cloud-iam-change-investigation-demo/README.md"
    )

    for text in [architecture, reviewer_pack]:
        assert "fixed time windows" in text
        assert "fixed entity or scope keys" in text
        assert "fixed event families or rule-local family sets" in text

    assert "evidence family" in config_demo
    assert "cross-host, cross-account, or cross-source global attribution" in config_demo
    assert "rule-local event family set" in cloud_iam_demo
    assert "whole-dataset attribution" in cloud_iam_demo


def test_architecture_doc_keeps_local_file_based_boundaries() -> None:
    architecture = _read_repo_file("docs/architecture.md")

    assert "flowchart TD" in architecture
    assert "local, file-based detection workflow lab" in architecture
    assert "Artifact names are reviewer-visible contracts" in architecture
    assert "does not provide production monitoring" in architecture

    for _, demo_name, _ in REVIEWER_DEMO_MATRIX:
        assert f"`{demo_name}`" in architecture
