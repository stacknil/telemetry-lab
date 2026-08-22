from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Final


class RunManifestVersionError(ValueError):
    """Raised when a run manifest cannot select one exact supported schema."""


@dataclass(frozen=True)
class RunManifestSchemaSelection:
    """The exact schema contract selected by a run manifest marker."""

    schema_version: str
    schema_path: PurePosixPath


RUN_MANIFEST_SCHEMA_REGISTRY: Final[Mapping[str, PurePosixPath]] = MappingProxyType(
    {
        "run-manifest/v1": PurePosixPath("schemas/run_manifest.schema.json"),
        "run-manifest/v2": PurePosixPath("schemas/run_manifest.v2.schema.json"),
    }
)


def select_run_manifest_schema(manifest: object) -> RunManifestSchemaSelection:
    """Select a schema by exact version marker, rejecting missing or unknown markers."""
    if not isinstance(manifest, Mapping):
        raise RunManifestVersionError("run manifest must be a JSON object")

    artifact_versions = manifest.get("artifact_schema_versions")
    if not isinstance(artifact_versions, Mapping):
        raise RunManifestVersionError(
            "artifact_schema_versions must be a JSON object"
        )
    if "run_manifest" not in artifact_versions:
        raise RunManifestVersionError(
            "artifact_schema_versions.run_manifest is required"
        )

    schema_version = artifact_versions["run_manifest"]
    if not isinstance(schema_version, str) or not schema_version.strip():
        raise RunManifestVersionError(
            "artifact_schema_versions.run_manifest must be a non-empty string"
        )

    schema_path = RUN_MANIFEST_SCHEMA_REGISTRY.get(schema_version)
    if schema_path is None:
        supported_versions = ", ".join(sorted(RUN_MANIFEST_SCHEMA_REGISTRY))
        raise RunManifestVersionError(
            f"unsupported run manifest schema version {schema_version!r}; "
            f"supported versions: {supported_versions}"
        )

    return RunManifestSchemaSelection(
        schema_version=schema_version,
        schema_path=schema_path,
    )
