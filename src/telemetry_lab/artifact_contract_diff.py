from __future__ import annotations

import json
import os
from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Final


REPORT_SCHEMA_VERSION: Final = "artifact-contract-diff/v1"
TEXT_SUFFIXES: Final = frozenset({".csv", ".json", ".jsonl", ".md", ".txt"})
RUN_MANIFEST_DIGEST_FIELDS: Final = (
    "input_digest",
    "config_digest",
    "input_file_digests",
    "config_file_digests",
)


class ArtifactContractDiffError(ValueError):
    """Raised when artifact trees cannot be compared safely."""


@dataclass(frozen=True)
class ArtifactSnapshot:
    comparison_digest: str
    comparison_size_bytes: int
    structure: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "comparison_digest": self.comparison_digest,
            "comparison_size_bytes": self.comparison_size_bytes,
        }
        if self.structure is not None:
            result["structure"] = deepcopy(dict(self.structure))
        return result


@dataclass(frozen=True)
class ArtifactDifference:
    path: str
    status: str
    artifact_kind: str
    change_reasons: tuple[str, ...]
    expected: ArtifactSnapshot | None = None
    actual: ArtifactSnapshot | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "path": self.path,
            "status": self.status,
            "artifact_kind": self.artifact_kind,
            "change_reasons": list(self.change_reasons),
        }
        if self.expected is not None:
            result["expected"] = self.expected.to_dict()
        if self.actual is not None:
            result["actual"] = self.actual.to_dict()
        return result


@dataclass(frozen=True)
class ArtifactContractDiffReport:
    expected_files: int
    actual_files: int
    unchanged_files: int
    missing_files: int
    extra_files: int
    changed_files: int
    differences: tuple[ArtifactDifference, ...]
    presence_only_paths: tuple[str, ...]

    @property
    def has_differences(self) -> bool:
        return bool(self.differences)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "status": "changed" if self.has_differences else "unchanged",
            "summary": {
                "expected_files": self.expected_files,
                "actual_files": self.actual_files,
                "unchanged_files": self.unchanged_files,
                "missing_files": self.missing_files,
                "extra_files": self.extra_files,
                "changed_files": self.changed_files,
                "presence_only_files": len(self.presence_only_paths),
            },
            "differences": [difference.to_dict() for difference in self.differences],
            "presence_only_paths": list(self.presence_only_paths),
        }


def compare_artifact_trees(
    expected_root: Path,
    actual_root: Path,
    *,
    excluded_paths: Iterable[Path] = (),
) -> ArtifactContractDiffReport:
    """Compare two artifact roots without leaking their absolute locations."""
    expected_root = _validated_root(expected_root, "expected")
    actual_root = _validated_root(actual_root, "actual")
    excluded = {path.resolve(strict=False) for path in excluded_paths}
    expected = _inventory(expected_root, excluded)
    actual = _inventory(actual_root, excluded)
    differences: list[ArtifactDifference] = []
    presence_only: list[str] = []
    unchanged = missing = extra = changed = 0

    for relative_path in sorted(expected.keys() | actual.keys()):
        expected_path = expected.get(relative_path)
        actual_path = actual.get(relative_path)
        kind = _artifact_kind(relative_path)
        if expected_path is None:
            extra += 1
            differences.append(
                ArtifactDifference(
                    path=relative_path,
                    status="extra",
                    artifact_kind=kind,
                    change_reasons=("extra-in-actual",),
                    actual=_snapshot(actual_path, relative_path, kind),
                )
            )
        elif actual_path is None:
            missing += 1
            differences.append(
                ArtifactDifference(
                    path=relative_path,
                    status="missing",
                    artifact_kind=kind,
                    change_reasons=("missing-from-actual",),
                    expected=_snapshot(expected_path, relative_path, kind),
                )
            )
        elif kind == "binary":
            presence_only.append(relative_path)
        else:
            expected_snapshot = _snapshot(expected_path, relative_path, kind)
            actual_snapshot = _snapshot(actual_path, relative_path, kind)
            if expected_snapshot.comparison_digest == actual_snapshot.comparison_digest:
                unchanged += 1
                continue
            changed += 1
            differences.append(
                ArtifactDifference(
                    path=relative_path,
                    status="changed",
                    artifact_kind=kind,
                    change_reasons=_change_reasons(expected_snapshot, actual_snapshot),
                    expected=expected_snapshot,
                    actual=actual_snapshot,
                )
            )

    return ArtifactContractDiffReport(
        expected_files=len(expected),
        actual_files=len(actual),
        unchanged_files=unchanged,
        missing_files=missing,
        extra_files=extra,
        changed_files=changed,
        differences=tuple(differences),
        presence_only_paths=tuple(presence_only),
    )


def _validated_root(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise ArtifactContractDiffError(f"{label} root must not be a symlink")
    resolved = path.resolve()
    if not resolved.is_dir():
        raise ArtifactContractDiffError(f"{label} root must be an existing directory")
    return resolved


def _inventory(root: Path, excluded: set[Path]) -> dict[str, Path]:
    inventory: dict[str, Path] = {}
    for current, dir_names, file_names in os.walk(
        root,
        followlinks=False,
        onerror=_raise_walk_error,
    ):
        current_path = Path(current)
        dir_names.sort()
        file_names.sort()
        for name in dir_names:
            if (current_path / name).is_symlink():
                relative = (current_path / name).relative_to(root).as_posix()
                raise ArtifactContractDiffError(
                    f"artifact tree contains a directory symlink: {relative}"
                )
        for name in file_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise ArtifactContractDiffError(
                    f"artifact tree contains a file symlink: {relative}"
                )
            if path.resolve(strict=False) not in excluded:
                inventory[relative] = path
    return inventory


def _raise_walk_error(error: OSError) -> None:
    raise ArtifactContractDiffError("cannot traverse artifact tree") from error


def _artifact_kind(relative_path: str) -> str:
    suffix = Path(relative_path).suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix == ".jsonl":
        return "jsonl"
    if suffix in TEXT_SUFFIXES:
        return "text"
    return "binary"


def _snapshot(path: Path | None, relative_path: str, kind: str) -> ArtifactSnapshot:
    if path is None:
        raise ArtifactContractDiffError(f"artifact path is unavailable: {relative_path}")
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise ArtifactContractDiffError(f"cannot read artifact: {relative_path}") from exc
    if kind != "binary":
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ArtifactContractDiffError(
                f"text artifact is not valid UTF-8: {relative_path}"
            ) from exc
        content = text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    structure = _structured_summary(content, relative_path, kind)
    return ArtifactSnapshot(
        comparison_digest="sha256:" + sha256(content).hexdigest(),
        comparison_size_bytes=len(content),
        structure=structure,
    )


def _structured_summary(
    content: bytes, relative_path: str, kind: str
) -> dict[str, Any] | None:
    if kind not in {"json", "jsonl"}:
        return None
    text = content.decode("utf-8")
    if kind == "json":
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ArtifactContractDiffError(
                f"invalid json artifact at {relative_path}:{exc.lineno}:{exc.colno}"
            ) from exc
        records = value if isinstance(value, list) else [value]
        container = _json_container(value)
    else:
        records = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ArtifactContractDiffError(
                    f"invalid jsonl artifact at "
                    f"{relative_path}:{line_number}:{exc.colno}"
                ) from exc
        value = records
        container = "jsonl"

    mappings = [record for record in records if isinstance(record, Mapping)]
    summary: dict[str, Any] = {
        "container": container,
        "record_count": len(records),
        "top_level_keys": sorted({key for record in mappings for key in record}),
    }
    schema_versions = _schema_versions(mappings)
    if schema_versions:
        summary["schema_versions"] = schema_versions
    if isinstance(value, Mapping):
        digests = {
            field: deepcopy(value[field])
            for field in RUN_MANIFEST_DIGEST_FIELDS
            if field in value
        }
        if digests:
            summary["run_manifest_digests"] = digests
    return summary


def _schema_versions(records: list[Mapping[str, Any]]) -> dict[str, list[str]]:
    markers: dict[str, set[str]] = {}
    for record in records:
        for field in ("$id", "$schema", "schema_id", "schema_version"):
            if isinstance(record.get(field), str):
                markers.setdefault(field, set()).add(record[field])
        artifact_versions = record.get("artifact_schema_versions")
        if isinstance(artifact_versions, Mapping):
            for field, value in artifact_versions.items():
                if isinstance(field, str) and isinstance(value, str):
                    markers.setdefault(
                        f"artifact_schema_versions.{field}", set()
                    ).add(value)
    return {field: sorted(values) for field, values in sorted(markers.items())}


def _json_container(value: object) -> str:
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, list):
        return "array"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    return "string"


def _change_reasons(
    expected: ArtifactSnapshot, actual: ArtifactSnapshot
) -> tuple[str, ...]:
    reasons = ["content-changed"]
    expected_structure = expected.structure or {}
    actual_structure = actual.structure or {}
    structural_fields = ("container", "record_count", "top_level_keys")
    if any(
        expected_structure.get(field) != actual_structure.get(field)
        for field in structural_fields
    ):
        reasons.append("structure-changed")
    if expected_structure.get("schema_versions") != actual_structure.get(
        "schema_versions"
    ):
        reasons.append("schema-version-changed")
    if expected_structure.get("run_manifest_digests") != actual_structure.get(
        "run_manifest_digests"
    ):
        reasons.append("run-manifest-digest-changed")
    return tuple(reasons)
