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


def _read_issue_template(name: str) -> str:
    return (REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / name).read_text(
        encoding="utf-8"
    )


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
    assert "[`docs/v1-contract-freeze.md`](docs/v1-contract-freeze.md)" in readme
    assert "[`docs/v1-readiness-gate.md`](docs/v1-readiness-gate.md)" in readme
    assert "[`docs/architecture.md`](docs/architecture.md)" in readme
    assert "Latest tagged release: [v1.0" in readme
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
        "operator-reproduction.md",
        "reviewer-path.md",
        "reviewer-brief.md",
        "v1-contract-freeze.md",
        "v1-readiness-gate.md",
        "release-v1.0.md",
        "release-v1.1.md",
        "v0.6-to-v1-artifact-diff.md",
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
    assert "[`docs/v1-contract-freeze.md`](v1-contract-freeze.md)" in reviewer_pack
    assert "[`docs/v1-readiness-gate.md`](v1-readiness-gate.md)" in reviewer_pack
    assert "[`docs/release-v1.0.md`](release-v1.0.md)" in reviewer_pack
    assert "[`docs/v0.6-to-v1-artifact-diff.md`](v0.6-to-v1-artifact-diff.md)" in reviewer_pack
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
    assert "v1.0 five-demo contract freeze checklist" in reviewer_pack
    assert "fixed inputs, fixed outputs, schema validation, artifact regeneration, and test pass" in reviewer_pack
    assert "five-demo matrix stable" in reviewer_pack
    assert "reviewer-visible artifact names stable" in reviewer_pack
    assert "package metadata, and repository metadata" in reviewer_pack
    assert "Regenerate and inspect committed artifacts" in reviewer_pack
    assert "Run `pytest`" in reviewer_pack
    assert "reviewer-facing artifact diff" in reviewer_pack
    assert "added fields, removed fields, semantic changes, and compatibility notes" in reviewer_pack
    assert "Do not add SIEM, dashboard, alert routing" in reviewer_pack
    assert "[`docs/v1-readiness-gate.md`](v1-readiness-gate.md)" in roadmap
    assert "[`v1 readiness gate`](docs/v1-readiness-gate.md)" in readme


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
    assert "v1.1 theme: Operator Reproduction Release." in current_docs["docs/roadmap.md"]
    assert "v1.1 is an Operator Reproduction Release, not a new-demo release" in current_docs["README.md"]
    assert "v1.0 Five-Demo Contract Freeze" in current_docs["docs/roadmap.md"]
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


def test_v1_contract_freeze_documents_release_drift_and_gate() -> None:
    freeze_doc = _read_repo_file("docs/v1-contract-freeze.md")
    docs_index = _read_repo_file("docs/README.md")
    reviewer_pack = _read_repo_file("docs/reviewer-pack.md")
    readme = _read_repo_file("README.md")
    roadmap = _read_repo_file("docs/roadmap.md")

    assert "# v1.0 Five-Demo Contract Freeze" in freeze_doc
    assert "## Release Status" in freeze_doc
    assert "latest tagged release is `v1.0`" in freeze_doc
    assert "`v0.6.0` remains the fourth-demo compatibility baseline" in freeze_doc
    assert "No new demo should be added for v1.0" in freeze_doc
    assert "python scripts/regenerate_artifacts.py --check" in freeze_doc
    assert "v1.0 artifact drift gate" in freeze_doc
    assert "[`docs/v1-readiness-gate.md`](v1-readiness-gate.md)" in freeze_doc
    assert "Do not publish v1.0 as a feature expansion" in freeze_doc

    for demo_name in [
        "telemetry-window-demo",
        "ai-assisted-detection-demo",
        "rule-evaluation-and-dedup-demo",
        "config-change-investigation-demo",
        "cloud-iam-change-investigation-demo",
    ]:
        assert f"`{demo_name}`" in freeze_doc

    for text in [docs_index, reviewer_pack, readme, roadmap]:
        assert "v1-contract-freeze.md" in text

    assert "v1.0 Five-Demo Contract Freeze" in roadmap


def test_v1_readiness_gate_defines_required_release_conditions() -> None:
    readiness_gate = _read_repo_file("docs/v1-readiness-gate.md")
    docs_index = _read_repo_file("docs/README.md")
    reviewer_pack = _read_repo_file("docs/reviewer-pack.md")
    readme = _read_repo_file("README.md")

    assert "# v1.0 Readiness Gate" in readiness_gate
    assert "If any condition fails, v1.0 is not ready." in readiness_gate

    for heading in [
        "## Fixed Inputs",
        "## Fixed Outputs",
        "## Schema Validation",
        "## Artifact Regeneration",
        "## Test Pass",
        "## Release Decision",
    ]:
        assert heading in readiness_gate

    for required_phrase in [
        "Fixed inputs",
        "Fixed outputs",
        "Schema validation",
        "Artifact regeneration",
        "Test pass",
        "python scripts/regenerate_artifacts.py --check",
        "python -m pytest tests/test_evidence_pipeline_schemas.py",
        "python -m pytest",
    ]:
        assert required_phrase in readiness_gate

    for text in [docs_index, reviewer_pack, readme]:
        assert "v1-readiness-gate.md" in text

    for demo_name in [
        "telemetry-window-demo",
        "ai-assisted-detection-demo",
        "rule-evaluation-and-dedup-demo",
        "config-change-investigation-demo",
        "cloud-iam-change-investigation-demo",
    ]:
        assert f"`{demo_name}`" in readiness_gate


def test_v06_to_v1_artifact_diff_documents_additive_fifth_demo_contract() -> None:
    artifact_diff = _read_repo_file("docs/v0.6-to-v1-artifact-diff.md")
    docs_index = _read_repo_file("docs/README.md")
    reviewer_pack = _read_repo_file("docs/reviewer-pack.md")
    readme = _read_repo_file("README.md")
    freeze_doc = _read_repo_file("docs/v1-contract-freeze.md")
    readiness_gate = _read_repo_file("docs/v1-readiness-gate.md")
    roadmap = _read_repo_file("docs/roadmap.md")

    assert "# v0.6.0 to v1 Artifact Contract Diff" in artifact_diff
    assert "additive-compatible" in artifact_diff
    assert "No fourth-demo artifact path was removed or renamed." in artifact_diff
    assert "The committed fourth-demo artifacts are unchanged" in artifact_diff
    assert "## Fourth-Demo Artifacts" in artifact_diff
    assert "## Fifth-Demo Artifacts" in artifact_diff
    assert "## Semantic Differences" in artifact_diff
    assert "## v1 Contract Additions" in artifact_diff
    assert "## Consumer Guidance" in artifact_diff
    assert "## Verification" in artifact_diff
    assert "`investigation_hits.json`" in artifact_diff
    assert "`investigation_signals.json`" in artifact_diff
    assert "`schemas/config_change_events.schema.json`" in artifact_diff
    assert "`schemas/config_investigation_hits.schema.json`" in artifact_diff
    assert "`schemas/cloudtrail_normalized_events.schema.json`" in artifact_diff
    assert "`schemas/investigation_summary.schema.json`" in artifact_diff
    assert "`schemas/cloud_iam_findings.schema.json`" in artifact_diff
    assert "`schemas/cloud_iam_summary.schema.json`" in artifact_diff
    assert "Same basename, different demo-local contract" in artifact_diff
    assert "No live AWS account" in artifact_diff
    assert "final incident verdict" in artifact_diff

    for text in [
        docs_index,
        reviewer_pack,
        readme,
        freeze_doc,
        readiness_gate,
        roadmap,
    ]:
        assert "v0.6-to-v1-artifact-diff.md" in text


def test_v1_release_note_states_reviewer_contract_boundary() -> None:
    release_note = _read_repo_file("docs/release-v1.0.md")
    docs_index = _read_repo_file("docs/README.md")
    reviewer_pack = _read_repo_file("docs/reviewer-pack.md")
    readme = _read_repo_file("README.md")
    freeze_doc = _read_repo_file("docs/v1-contract-freeze.md")
    readiness_gate = _read_repo_file("docs/v1-readiness-gate.md")

    boundary = "This is a reviewer-contract release, not a production SIEM."

    assert "# v1.0 Reviewer Contract Release Notes" in release_note
    assert boundary in release_note
    assert "Release status: v1.0 reviewer-contract release." in release_note
    assert "## Release Scope" in release_note
    assert "## Reviewer Contract" in release_note
    assert "## Artifact Compatibility" in release_note
    assert "## Validation Snapshot" in release_note
    assert "## Boundaries" in release_note
    assert "python scripts/regenerate_artifacts.py --check" in release_note
    assert "python -m pytest tests/test_evidence_pipeline_schemas.py" in release_note
    assert "python -m pytest" in release_note
    assert "This release does not claim production readiness." in release_note

    for demo_name in [
        "telemetry-window-demo",
        "ai-assisted-detection-demo",
        "rule-evaluation-and-dedup-demo",
        "config-change-investigation-demo",
        "cloud-iam-change-investigation-demo",
    ]:
        assert f"`{demo_name}`" in release_note

    for text in [docs_index, reviewer_pack, readme, freeze_doc, readiness_gate]:
        assert "release-v1.0.md" in text

    assert boundary in freeze_doc
    assert boundary in readiness_gate


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


def test_operator_reproduction_doc_and_readme_define_short_gate() -> None:
    operator_doc = _read_repo_file("docs/operator-reproduction.md")
    docs_index = _read_repo_file("docs/README.md")
    readme = _read_repo_file("README.md")
    roadmap = _read_repo_file("docs/roadmap.md")

    assert "# Operator Reproduction" in operator_doc
    assert "git clone https://github.com/stacknil/telemetry-lab.git" in operator_doc
    assert "python -m pip install -e \".[dev]\"" in operator_doc
    assert "## Run The Five Demos" in operator_doc
    for demo_command in [
        "python -m telemetry_window_demo.cli run --config configs/default.yaml",
        "python -m telemetry_window_demo.cli run-ai-demo",
        "python -m telemetry_window_demo.cli run-rule-dedup-demo",
        "python -m telemetry_window_demo.cli run-config-change-demo",
        "python -m telemetry_window_demo.cli run-cloud-iam-change-demo",
    ]:
        assert demo_command in operator_doc
    assert "python scripts/regenerate_artifacts.py --check" in operator_doc
    assert "python -m pytest tests/test_evidence_pipeline_schemas.py" in operator_doc
    assert "python -m pytest" in operator_doc
    assert "python scripts/check_release_contract.py" in operator_doc
    assert "does not add a new demo" in operator_doc
    assert "does not claim production readiness" in operator_doc

    assert "## Verify Locally In 3 Commands" in readme
    assert "If you want to verify v1.0 locally, run these three commands." in readme
    assert "docs/operator-reproduction.md" in readme
    assert "operator-reproduction.md" in docs_index
    assert "scripts/check_release_contract.py" in roadmap


def test_operator_issue_templates_keep_reviewer_contract_scope() -> None:
    issue_template_dir = REPO_ROOT / ".github" / "ISSUE_TEMPLATE"
    templates = {
        "schema-drift-report.md": _read_issue_template("schema-drift-report.md"),
        "artifact-regeneration-failure.md": _read_issue_template(
            "artifact-regeneration-failure.md"
        ),
        "demo-boundary-question.md": _read_issue_template("demo-boundary-question.md"),
        "docs-reproduction-question.md": _read_issue_template(
            "docs-reproduction-question.md"
        ),
    }
    feature_template = _read_issue_template("feature_request.yml")

    assert issue_template_dir.is_dir()
    for name, text in templates.items():
        assert (issue_template_dir / name).is_file()
        assert "reviewer-contract" in text
        assert "No real account IDs, credentials" in text or "No live AWS account" in text
        assert "dashboard" in text
        assert "case" in text.lower()

    assert "python -m pytest tests/test_evidence_pipeline_schemas.py" in templates[
        "schema-drift-report.md"
    ]
    assert "python scripts/regenerate_artifacts.py --check" in templates[
        "artifact-regeneration-failure.md"
    ]
    assert "No new demo expansion for v1.1." in templates["demo-boundary-question.md"]
    assert "documentation mismatch" in templates["docs-reproduction-question.md"]
    assert "This is not a request for a new demo." in templates[
        "docs-reproduction-question.md"
    ]
    assert "next demo" not in feature_template.lower()


def test_v11_release_note_keeps_operator_reproduction_scope() -> None:
    release_note = _read_repo_file("docs/release-v1.1.md")
    docs_index = _read_repo_file("docs/README.md")
    readme = _read_repo_file("README.md")
    roadmap = _read_repo_file("docs/roadmap.md")

    assert "# v1.1 Operator Reproduction Release Notes (Draft)" in release_note
    assert "Theme: operator reproduction and issue triage, no demo expansion." in release_note
    assert "Release status: draft" in release_note
    assert "python scripts/check_release_contract.py" in release_note
    assert "documentation reproduction questions" in release_note

    for demo_name in [
        "telemetry-window-demo",
        "ai-assisted-detection-demo",
        "rule-evaluation-and-dedup-demo",
        "config-change-investigation-demo",
        "cloud-iam-change-investigation-demo",
    ]:
        assert f"`{demo_name}`" in release_note

    for forbidden_scope in [
        "No demo expansion.",
        "No live ingestion.",
        "No production SIEM or dashboard.",
        "No alert routing or case-management service.",
        "No autonomous response.",
        "No final incident verdict.",
    ]:
        assert forbidden_scope in release_note

    for text in [docs_index, readme, roadmap]:
        assert "release-v1.1.md" in text
