from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


REPO_ROOT = Path(__file__).resolve().parents[1]

SCHEMA_CONTRACTS = {
    "schemas/telemetry_summary.schema.json": [
        "data/processed/summary.json",
        "data/processed/richer_sample/summary.json",
    ],
    "schemas/rule_hits.schema.json": [
        "demos/ai-assisted-detection-demo/artifacts/rule_hits.json",
    ],
    "schemas/case_bundles.schema.json": [
        "demos/ai-assisted-detection-demo/artifacts/case_bundles.json",
    ],
    "schemas/dedup_explanations.schema.json": [
        "demos/rule-evaluation-and-dedup-demo/artifacts/dedup_explanations.json",
    ],
    "schemas/investigation_summary.schema.json": [
        "demos/config-change-investigation-demo/artifacts/investigation_summary.json",
    ],
    "schemas/cloud_iam_findings.schema.json": [
        "demos/cloud-iam-change-investigation-demo/artifacts/investigation_signals.json",
    ],
    "schemas/cloud_iam_summary.schema.json": [
        "demos/cloud-iam-change-investigation-demo/artifacts/investigation_summary.json",
    ],
}

DEMO_SCHEMA_COVERAGE = {
    "telemetry-window-demo": [
        "schemas/telemetry_summary.schema.json",
    ],
    "ai-assisted-detection-demo": [
        "schemas/rule_hits.schema.json",
        "schemas/case_bundles.schema.json",
    ],
    "rule-evaluation-and-dedup-demo": [
        "schemas/dedup_explanations.schema.json",
    ],
    "config-change-investigation-demo": [
        "schemas/investigation_summary.schema.json",
    ],
    "cloud-iam-change-investigation-demo": [
        "schemas/cloud_iam_findings.schema.json",
        "schemas/cloud_iam_summary.schema.json",
    ],
}


def _load_json(relative_path: str) -> object:
    return json.loads((REPO_ROOT / relative_path).read_text(encoding="utf-8"))


def _error_summary(errors: list[object]) -> str:
    lines: list[str] = []
    for error in errors[:5]:
        path = ".".join(str(part) for part in error.absolute_path) or "<root>"
        lines.append(f"{path}: {error.message}")
    return "\n".join(lines)


def test_evidence_pipeline_schemas_validate_committed_artifacts() -> None:
    for schema_path, artifact_paths in SCHEMA_CONTRACTS.items():
        schema = _load_json(schema_path)
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())

        for artifact_path in artifact_paths:
            errors = sorted(
                validator.iter_errors(_load_json(artifact_path)),
                key=lambda error: list(error.absolute_path),
            )
            assert errors == [], f"{schema_path} failed for {artifact_path}\n{_error_summary(errors)}"


def test_evidence_pipeline_contract_docs_reference_schemas_and_artifacts() -> None:
    contract_doc = (REPO_ROOT / "docs" / "evidence-pipeline-contract.md").read_text(
        encoding="utf-8"
    )
    reviewer_pack = (REPO_ROOT / "docs" / "reviewer-pack.md").read_text(
        encoding="utf-8"
    )
    docs_index = (REPO_ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert "Evidence Pipeline Contract" in contract_doc
    assert "evidence-pipeline-contract.md" in reviewer_pack
    assert "evidence-pipeline-contract.md" in docs_index
    assert "docs/evidence-pipeline-contract.md" in readme

    for schema_path, artifact_paths in SCHEMA_CONTRACTS.items():
        assert f"`{schema_path}`" in contract_doc
        assert f"`{schema_path}`" in reviewer_pack
        assert (REPO_ROOT / schema_path).is_file(), schema_path
        for artifact_path in artifact_paths:
            assert f"`{artifact_path}`" in contract_doc
            assert (REPO_ROOT / artifact_path).is_file(), artifact_path


def test_schema_contracts_cover_all_five_demos_and_named_artifacts() -> None:
    contract_schema_paths = set(SCHEMA_CONTRACTS)

    assert set(DEMO_SCHEMA_COVERAGE) == {
        "telemetry-window-demo",
        "ai-assisted-detection-demo",
        "rule-evaluation-and-dedup-demo",
        "config-change-investigation-demo",
        "cloud-iam-change-investigation-demo",
    }
    for demo_name, schema_paths in DEMO_SCHEMA_COVERAGE.items():
        assert schema_paths, demo_name
        for schema_path in schema_paths:
            assert schema_path in contract_schema_paths
            assert (REPO_ROOT / schema_path).is_file(), schema_path

    for required_schema in [
        "schemas/rule_hits.schema.json",
        "schemas/case_bundles.schema.json",
        "schemas/dedup_explanations.schema.json",
        "schemas/investigation_summary.schema.json",
        "schemas/cloud_iam_findings.schema.json",
    ]:
        assert required_schema in contract_schema_paths
