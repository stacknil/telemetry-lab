from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


REPO_ROOT = Path(__file__).resolve().parents[1]

SCHEMA_CONTRACTS = {
    "schemas/telemetry_summary.schema.json": [
        "data/processed/summary.json",
        "data/processed/richer_sample/summary.json",
    ],
    "schemas/run_manifest.schema.json": [
        "data/processed/run_manifest.json",
        "data/processed/richer_sample/run_manifest.json",
        "demos/ai-assisted-detection-demo/artifacts/run_manifest.json",
        "demos/rule-evaluation-and-dedup-demo/artifacts/run_manifest.json",
        "demos/config-change-investigation-demo/artifacts/run_manifest.json",
        "demos/cloud-iam-change-investigation-demo/artifacts/run_manifest.json",
    ],
    "schemas/rule_hits.schema.json": [
        "demos/ai-assisted-detection-demo/artifacts/rule_hits.json",
    ],
    "schemas/case_bundles.schema.json": [
        "demos/ai-assisted-detection-demo/artifacts/case_bundles.json",
    ],
    "schemas/case_summaries.schema.json": [
        "demos/ai-assisted-detection-demo/artifacts/case_summaries.json",
    ],
    "schemas/ai_audit_traces.schema.json": [
        "demos/ai-assisted-detection-demo/artifacts/audit_traces.jsonl",
    ],
    "schemas/dedup_rule_hits.schema.json": [
        "demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_before_dedup.json",
        "demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_after_dedup.json",
    ],
    "schemas/dedup_explanations.schema.json": [
        "demos/rule-evaluation-and-dedup-demo/artifacts/dedup_explanations.json",
    ],
    "schemas/config_change_events.schema.json": [
        "demos/config-change-investigation-demo/artifacts/change_events_normalized.json",
    ],
    "schemas/config_investigation_hits.schema.json": [
        "demos/config-change-investigation-demo/artifacts/investigation_hits.json",
    ],
    "schemas/investigation_summary.schema.json": [
        "demos/config-change-investigation-demo/artifacts/investigation_summary.json",
    ],
    "schemas/cloudtrail_normalized_events.schema.json": [
        "demos/cloud-iam-change-investigation-demo/artifacts/normalized_cloudtrail_events.json",
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
        "schemas/run_manifest.schema.json",
        "schemas/telemetry_summary.schema.json",
    ],
    "ai-assisted-detection-demo": [
        "schemas/run_manifest.schema.json",
        "schemas/rule_hits.schema.json",
        "schemas/case_bundles.schema.json",
        "schemas/case_summaries.schema.json",
        "schemas/ai_audit_traces.schema.json",
    ],
    "rule-evaluation-and-dedup-demo": [
        "schemas/run_manifest.schema.json",
        "schemas/dedup_rule_hits.schema.json",
        "schemas/dedup_explanations.schema.json",
    ],
    "config-change-investigation-demo": [
        "schemas/run_manifest.schema.json",
        "schemas/config_change_events.schema.json",
        "schemas/config_investigation_hits.schema.json",
        "schemas/investigation_summary.schema.json",
    ],
    "cloud-iam-change-investigation-demo": [
        "schemas/run_manifest.schema.json",
        "schemas/cloudtrail_normalized_events.schema.json",
        "schemas/cloud_iam_findings.schema.json",
        "schemas/cloud_iam_summary.schema.json",
    ],
}

REVIEWER_JSON_ARTIFACTS = {
    "data/processed/summary.json",
    "data/processed/run_manifest.json",
    "data/processed/richer_sample/summary.json",
    "data/processed/richer_sample/run_manifest.json",
    "demos/ai-assisted-detection-demo/artifacts/rule_hits.json",
    "demos/ai-assisted-detection-demo/artifacts/case_bundles.json",
    "demos/ai-assisted-detection-demo/artifacts/case_summaries.json",
    "demos/ai-assisted-detection-demo/artifacts/audit_traces.jsonl",
    "demos/ai-assisted-detection-demo/artifacts/run_manifest.json",
    "demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_before_dedup.json",
    "demos/rule-evaluation-and-dedup-demo/artifacts/rule_hits_after_dedup.json",
    "demos/rule-evaluation-and-dedup-demo/artifacts/dedup_explanations.json",
    "demos/rule-evaluation-and-dedup-demo/artifacts/run_manifest.json",
    "demos/config-change-investigation-demo/artifacts/change_events_normalized.json",
    "demos/config-change-investigation-demo/artifacts/investigation_hits.json",
    "demos/config-change-investigation-demo/artifacts/investigation_summary.json",
    "demos/config-change-investigation-demo/artifacts/run_manifest.json",
    "demos/cloud-iam-change-investigation-demo/artifacts/normalized_cloudtrail_events.json",
    "demos/cloud-iam-change-investigation-demo/artifacts/investigation_signals.json",
    "demos/cloud-iam-change-investigation-demo/artifacts/investigation_summary.json",
    "demos/cloud-iam-change-investigation-demo/artifacts/run_manifest.json",
}


def _load_json(relative_path: str) -> object:
    return json.loads((REPO_ROOT / relative_path).read_text(encoding="utf-8"))


def _load_jsonl(relative_path: str) -> list[object]:
    return [
        json.loads(line)
        for line in (REPO_ROOT / relative_path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _load_artifact(relative_path: str) -> object:
    if relative_path.endswith(".jsonl"):
        return _load_jsonl(relative_path)
    return _load_json(relative_path)


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
            artifact = _load_artifact(artifact_path)
            if artifact_path.endswith(".jsonl"):
                assert isinstance(artifact, list)
                errors = [
                    error
                    for record in artifact
                    for error in validator.iter_errors(record)
                ]
                errors.sort(key=lambda error: list(error.absolute_path))
            else:
                errors = sorted(
                    validator.iter_errors(artifact),
                    key=lambda error: list(error.absolute_path),
                )
            assert errors == [], f"{schema_path} failed for {artifact_path}\n{_error_summary(errors)}"


def test_run_manifest_schema_keeps_legacy_v12_shape_compatible() -> None:
    schema = _load_json("schemas/run_manifest.schema.json")
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    legacy_manifest = {
        "tool_version": "1.2.0",
        "demo_id": "window",
        "input_digest": "sha256:" + "0" * 64,
        "config_digest": "sha256:" + "1" * 64,
        "artifact_schema_versions": {"run_manifest": "run-manifest/v1"},
        "execution_mode": "synthetic-local",
    }

    errors = sorted(
        validator.iter_errors(legacy_manifest),
        key=lambda error: list(error.absolute_path),
    )

    assert errors == []


def test_committed_manifests_preserve_v12_aggregate_digests() -> None:
    expected = {
        "data/processed/run_manifest.json": (
            "sha256:c08795a6a3c361a3339414c5a8441fb74c58f027c96931dbdc0da28560e132ac",
            "sha256:b02cfeb006b05c52f075c3aa454045cd4c46b25be5576e37e184c3f02bf9328b",
        ),
        "data/processed/richer_sample/run_manifest.json": (
            "sha256:e8771283a83c146a2cffce5fe316c1408200b6d7717cbb6d074334aa891672f3",
            "sha256:e7cb0264262cc997edf8f6b987dc0466098f23150d0c6204fb5fd7c245df1d7d",
        ),
        "demos/ai-assisted-detection-demo/artifacts/run_manifest.json": (
            "sha256:e45f71682c89734e625119a3edd166591f1a0cdf6e3b24c7b87c23d809154b55",
            "sha256:183924db1f5800b56ec2794198d65489c49c0824823b52ef373bb30011886408",
        ),
        "demos/rule-evaluation-and-dedup-demo/artifacts/run_manifest.json": (
            "sha256:06c005b433bdc28f08cd6fdc7028c0242960b09f5187a723445f40bf135977a4",
            "sha256:aa18d8ca4edab237dcec5c23c1dc7e9433f23a7d156df5a592e353c6fc9b74ad",
        ),
        "demos/config-change-investigation-demo/artifacts/run_manifest.json": (
            "sha256:c7ee82071fa0ae47742c3241b20dd97e811df618757d008b99624b1afb686229",
            "sha256:c0db824d16bd1e23cb413e9d56ad6e1effa6168aea6c9ef3f8976118ff5a1d6e",
        ),
        "demos/cloud-iam-change-investigation-demo/artifacts/run_manifest.json": (
            "sha256:96c39405358a7ecd940e84742df41dc5636e829824a21103657e0aa4123cab66",
            "sha256:820e9a4beca0aeaf92485b5fd7177b1e3c7f6bd7cbe469cb0afc39e2ac51cce7",
        ),
    }

    for artifact_path, (input_digest, config_digest) in expected.items():
        manifest = _load_json(artifact_path)
        assert manifest["input_digest"] == input_digest
        assert manifest["config_digest"] == config_digest


def test_cci_003_traces_to_investigation_summary_schema() -> None:
    """Reviewer trace for issue #76: CCI-003 -> investigation_summary schema."""
    schema = _load_json("schemas/investigation_summary.schema.json")
    Draft202012Validator.check_schema(schema)
    # The top-level schema describes the array artifact; validate one traced
    # record against the per-item schema so this reads as a single-object trace.
    validator = Draft202012Validator(schema["items"], format_checker=FormatChecker())

    artifact = _load_json(
        "demos/config-change-investigation-demo/artifacts/investigation_summary.json"
    )
    records = {record["investigation_id"]: record for record in artifact}
    assert "CCI-003" in records, "CCI-003 is missing from investigation_summary.json"

    cci_003 = records["CCI-003"]
    assert cci_003["target_system"] == "vault-gateway"
    assert cci_003["triggering_change_id"] == "cfg-004"

    errors = sorted(
        validator.iter_errors(cci_003), key=lambda error: list(error.absolute_path)
    )
    assert errors == [], f"CCI-003 failed schema validation\n{_error_summary(errors)}"

    assert re.fullmatch(r"CCI-[0-9]{3}", cci_003["investigation_id"])
    assert cci_003["severity"] in {"low", "medium", "high", "critical"}
    assert cci_003["evidence_counts"]["policy_denials"] >= 0
    assert cci_003["evidence_counts"]["follow_on_events"] >= 0
    assert isinstance(cci_003["evidence_counts"]["policy_denials"], int)
    assert isinstance(cci_003["evidence_counts"]["follow_on_events"], int)


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
    contracted_artifact_paths = {
        artifact_path
        for artifact_paths in SCHEMA_CONTRACTS.values()
        for artifact_path in artifact_paths
    }

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
        "schemas/run_manifest.schema.json",
        "schemas/rule_hits.schema.json",
        "schemas/case_bundles.schema.json",
        "schemas/dedup_explanations.schema.json",
        "schemas/investigation_summary.schema.json",
        "schemas/cloud_iam_findings.schema.json",
    ]:
        assert required_schema in contract_schema_paths

    assert contracted_artifact_paths == REVIEWER_JSON_ARTIFACTS
    for artifact_path in REVIEWER_JSON_ARTIFACTS:
        assert (REPO_ROOT / artifact_path).is_file(), artifact_path
