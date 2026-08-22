from __future__ import annotations

import codecs
import io
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO, Final, Literal, TypeAlias


REPORT_SCHEMA_VERSION: Final = "artifact-contract-diff/v1"
TEXT_ARTIFACT_SUFFIXES: Final = frozenset(
    {".csv", ".json", ".jsonl", ".md", ".txt"}
)
RUN_MANIFEST_DIGEST_FIELDS: Final = (
    "input_digest",
    "config_digest",
    "input_file_digests",
    "config_file_digests",
)
READ_CHUNK_SIZE: Final = 64 * 1024
MAX_ARTIFACT_FILES: Final = 10_000
MAX_RELATIVE_PATH_LENGTH: Final = 1_024
MAX_STRUCTURED_ARTIFACT_BYTES: Final = 64 * 1024 * 1024
MAX_STRUCTURAL_ITEMS: Final = 4_096
MAX_METADATA_STRING_LENGTH: Final = 1_024
MAX_DIGEST_ENTRIES: Final = 10_000

ArtifactKind: TypeAlias = Literal["json", "jsonl", "text", "binary"]
DifferenceStatus: TypeAlias = Literal["missing", "extra", "changed"]
ChangeReason: TypeAlias = Literal[
    "missing-from-actual",
    "extra-in-actual",
    "content-changed",
    "structure-changed",
    "schema-version-changed",
    "run-manifest-digest-changed",
]

_DIGEST_PATTERN: Final = re.compile(r"sha256:[0-9a-f]{64}")
_RELATIVE_PATH_PATTERN: Final = re.compile(
    r"^(?![A-Za-z]:)(?!.*\\)(?!.*(?:^|/)\.\.?(?:/|$))[^/]+(?:/[^/]+)*$"
)
_LOCAL_ABSOLUTE_PATH_PATTERN: Final = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/)")
_ALLOWED_CHANGE_REASONS: Final = frozenset(
    {
        "missing-from-actual",
        "extra-in-actual",
        "content-changed",
        "structure-changed",
        "schema-version-changed",
        "run-manifest-digest-changed",
    }
)


class ArtifactContractDiffError(ValueError):
    """Raised when artifact trees cannot be compared safely."""


@dataclass(frozen=True)
class ArtifactSnapshot:
    comparison_digest: str
    comparison_size_bytes: int
    structure: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if _DIGEST_PATTERN.fullmatch(self.comparison_digest) is None:
            raise ArtifactContractDiffError("snapshot comparison digest is invalid")
        if self.comparison_size_bytes < 0:
            raise ArtifactContractDiffError("snapshot comparison size must be non-negative")

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
    status: DifferenceStatus
    artifact_kind: ArtifactKind
    change_reasons: tuple[ChangeReason, ...]
    expected: ArtifactSnapshot | None = None
    actual: ArtifactSnapshot | None = None

    def __post_init__(self) -> None:
        if not _is_valid_relative_path(self.path):
            raise ArtifactContractDiffError("difference path must be a safe relative path")
        if self.artifact_kind not in {"json", "jsonl", "text", "binary"}:
            raise ArtifactContractDiffError("difference artifact kind is invalid")
        if not self.change_reasons or len(set(self.change_reasons)) != len(
            self.change_reasons
        ):
            raise ArtifactContractDiffError("difference reasons must be non-empty and unique")
        if not set(self.change_reasons) <= _ALLOWED_CHANGE_REASONS:
            raise ArtifactContractDiffError("difference reason is invalid")

        if self.status == "missing":
            valid = (
                self.change_reasons == ("missing-from-actual",)
                and self.expected is not None
                and self.actual is None
            )
        elif self.status == "extra":
            valid = (
                self.change_reasons == ("extra-in-actual",)
                and self.expected is None
                and self.actual is not None
            )
        elif self.status == "changed":
            valid = (
                self.change_reasons[0] == "content-changed"
                and "missing-from-actual" not in self.change_reasons
                and "extra-in-actual" not in self.change_reasons
                and self.expected is not None
                and self.actual is not None
                and self.artifact_kind != "binary"
            )
        else:
            raise ArtifactContractDiffError("difference status is invalid")
        if not valid:
            raise ArtifactContractDiffError(f"{self.status} difference is inconsistent")

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

    def __post_init__(self) -> None:
        counts = (
            self.expected_files,
            self.actual_files,
            self.unchanged_files,
            self.missing_files,
            self.extra_files,
            self.changed_files,
        )
        if any(count < 0 for count in counts):
            raise ArtifactContractDiffError("report counts must be non-negative")
        if self.expected_files > MAX_ARTIFACT_FILES or self.actual_files > MAX_ARTIFACT_FILES:
            raise ArtifactContractDiffError("artifact file count exceeds the report limit")

        status_counts = Counter(difference.status for difference in self.differences)
        if status_counts != Counter(
            {
                "missing": self.missing_files,
                "extra": self.extra_files,
                "changed": self.changed_files,
            }
        ):
            raise ArtifactContractDiffError("report difference counts are inconsistent")
        if self.expected_files != (
            self.unchanged_files
            + self.missing_files
            + self.changed_files
            + len(self.presence_only_paths)
        ):
            raise ArtifactContractDiffError("expected file count is inconsistent")
        if self.actual_files != (
            self.unchanged_files
            + self.extra_files
            + self.changed_files
            + len(self.presence_only_paths)
        ):
            raise ArtifactContractDiffError("actual file count is inconsistent")

        difference_paths = tuple(difference.path for difference in self.differences)
        if difference_paths != tuple(sorted(set(difference_paths))):
            raise ArtifactContractDiffError(
                "difference paths must be unique and sorted"
            )
        if self.presence_only_paths != tuple(sorted(set(self.presence_only_paths))):
            raise ArtifactContractDiffError(
                "presence-only paths must be unique and sorted"
            )
        if set(difference_paths) & set(self.presence_only_paths):
            raise ArtifactContractDiffError(
                "difference and presence-only paths must be disjoint"
            )

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


def normalize_artifact_text_bytes(content: bytes) -> bytes:
    """Normalize artifact newlines after validating strict UTF-8."""
    return b"".join(_iter_normalized_text_chunks((content,)))


def compare_artifact_trees(
    expected_root: Path,
    actual_root: Path,
) -> ArtifactContractDiffReport:
    """Compare two artifact roots without leaking their absolute locations."""
    expected_root = _validated_root(expected_root, "expected")
    actual_root = _validated_root(actual_root, "actual")
    expected = _inventory(expected_root)
    actual = _inventory(actual_root)
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
            expected_snapshot = _snapshot_identity(expected_path, relative_path, kind)
            actual_snapshot = _snapshot_identity(actual_path, relative_path, kind)
            if (
                expected_snapshot.comparison_digest
                == actual_snapshot.comparison_digest
                and expected_snapshot.comparison_size_bytes
                == actual_snapshot.comparison_size_bytes
            ):
                unchanged += 1
                continue
            expected_snapshot = _add_structure(
                expected_snapshot, expected_path, relative_path, kind
            )
            actual_snapshot = _add_structure(
                actual_snapshot, actual_path, relative_path, kind
            )
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
    try:
        if _is_link_like(path):
            raise ArtifactContractDiffError(f"{label} root must not be a symlink")
        root_mode = path.lstat().st_mode
        if not stat.S_ISDIR(root_mode):
            raise ArtifactContractDiffError(
                f"{label} root must be an existing directory"
            )
        return path.resolve(strict=True)
    except ArtifactContractDiffError:
        raise
    except OSError as exc:
        raise ArtifactContractDiffError(
            f"{label} root must be an existing directory"
        ) from exc


def _inventory(root: Path) -> dict[str, Path]:
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
            path = current_path / name
            if _is_link_like(path):
                relative = path.relative_to(root).as_posix()
                raise ArtifactContractDiffError(
                    f"artifact tree contains a directory symlink: {relative}"
                )
        for name in file_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            try:
                mode = path.lstat().st_mode
            except OSError as exc:
                raise ArtifactContractDiffError(
                    f"cannot inspect artifact: {relative}"
                ) from exc
            if stat.S_ISLNK(mode) or _is_link_like(path):
                raise ArtifactContractDiffError(
                    f"artifact tree contains a file symlink: {relative}"
                )
            if not stat.S_ISREG(mode):
                raise ArtifactContractDiffError(
                    f"artifact tree contains a non-regular artifact: {relative}"
                )
            if not _is_valid_relative_path(relative):
                raise ArtifactContractDiffError(
                    "artifact tree contains an unsafe relative path"
                )
            inventory[relative] = path
            if len(inventory) > MAX_ARTIFACT_FILES:
                raise ArtifactContractDiffError(
                    "artifact tree exceeds the report file-count limit"
                )
    return inventory


def _raise_walk_error(error: OSError) -> None:
    raise ArtifactContractDiffError("cannot traverse artifact tree") from error


def _is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    junction_check = getattr(path, "is_junction", None)
    return bool(junction_check is not None and junction_check())


def _is_valid_relative_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= MAX_RELATIVE_PATH_LENGTH
        and not any(ord(character) < 32 for character in value)
        and _RELATIVE_PATH_PATTERN.fullmatch(value) is not None
    )


def _artifact_kind(relative_path: str) -> ArtifactKind:
    suffix = Path(relative_path).suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix == ".jsonl":
        return "jsonl"
    if suffix in TEXT_ARTIFACT_SUFFIXES:
        return "text"
    return "binary"


def _snapshot(
    path: Path | None, relative_path: str, kind: ArtifactKind
) -> ArtifactSnapshot:
    snapshot = _snapshot_identity(path, relative_path, kind)
    if path is None:
        raise ArtifactContractDiffError(f"artifact path is unavailable: {relative_path}")
    return _add_structure(snapshot, path, relative_path, kind)


def _snapshot_identity(
    path: Path | None, relative_path: str, kind: ArtifactKind
) -> ArtifactSnapshot:
    if path is None:
        raise ArtifactContractDiffError(f"artifact path is unavailable: {relative_path}")
    digest = sha256()
    size = 0
    try:
        with _open_regular_binary(path, relative_path) as handle:
            chunks: Iterable[bytes] = iter(
                lambda: handle.read(READ_CHUNK_SIZE),
                b"",
            )
            if kind != "binary":
                chunks = _iter_normalized_text_chunks(chunks)
            for chunk in chunks:
                digest.update(chunk)
                size += len(chunk)
    except UnicodeDecodeError as exc:
        raise ArtifactContractDiffError(
            f"text artifact is not valid UTF-8: {relative_path}"
        ) from exc
    except OSError as exc:
        raise ArtifactContractDiffError(f"cannot read artifact: {relative_path}") from exc
    return ArtifactSnapshot(
        comparison_digest="sha256:" + digest.hexdigest(),
        comparison_size_bytes=size,
    )


@contextmanager
def _open_regular_binary(path: Path, relative_path: str) -> Iterator[BinaryIO]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ArtifactContractDiffError(
                f"artifact is not a regular file: {relative_path}"
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            yield handle
    except ArtifactContractDiffError:
        raise
    except OSError as exc:
        raise ArtifactContractDiffError(
            f"cannot open artifact safely: {relative_path}"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _iter_normalized_text_chunks(chunks: Iterable[bytes]) -> Iterator[bytes]:
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    pending_carriage_return = False
    for chunk in chunks:
        decoder.decode(chunk, final=False)
        if pending_carriage_return:
            chunk = b"\r" + chunk
            pending_carriage_return = False
        if chunk.endswith(b"\r"):
            chunk = chunk[:-1]
            pending_carriage_return = True
        normalized = chunk.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        if normalized:
            yield normalized
    decoder.decode(b"", final=True)
    if pending_carriage_return:
        yield b"\n"


def _add_structure(
    snapshot: ArtifactSnapshot,
    path: Path,
    relative_path: str,
    kind: ArtifactKind,
) -> ArtifactSnapshot:
    if kind not in {"json", "jsonl"}:
        return snapshot
    if snapshot.comparison_size_bytes > MAX_STRUCTURED_ARTIFACT_BYTES:
        raise ArtifactContractDiffError(
            f"structured artifact exceeds the {MAX_STRUCTURED_ARTIFACT_BYTES}-byte "
            f"summary limit: {relative_path}"
        )
    structure = _structured_summary(path, relative_path, kind)
    return replace(snapshot, structure=structure)


def _structured_summary(
    path: Path, relative_path: str, kind: ArtifactKind
) -> dict[str, Any]:
    if kind == "jsonl":
        return _jsonl_summary(path, relative_path)
    try:
        with _open_regular_binary(path, relative_path) as handle:
            content = normalize_artifact_text_bytes(handle.read())
    except UnicodeDecodeError as exc:
        raise ArtifactContractDiffError(
            f"text artifact is not valid UTF-8: {relative_path}"
        ) from exc
    except OSError as exc:
        raise ArtifactContractDiffError(f"cannot read artifact: {relative_path}") from exc
    try:
        value = json.loads(content.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ArtifactContractDiffError(
            f"invalid json artifact at {relative_path}:{exc.lineno}:{exc.colno}"
        ) from exc

    records = value if isinstance(value, list) else [value]
    return _summarize_records(
        records,
        container=_json_container(value),
        relative_path=relative_path,
        run_manifest=value if isinstance(value, Mapping) else None,
    )


def _jsonl_summary(path: Path, relative_path: str) -> dict[str, Any]:
    def records() -> Iterator[object]:
        try:
            with _open_regular_binary(path, relative_path) as raw_handle:
                with io.TextIOWrapper(
                    raw_handle,
                    encoding="utf-8",
                    errors="strict",
                    newline=None,
                ) as text_handle:
                    for line_number, line in enumerate(text_handle, start=1):
                        if not line.strip():
                            continue
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError as exc:
                            raise ArtifactContractDiffError(
                                f"invalid jsonl artifact at "
                                f"{relative_path}:{line_number}:{exc.colno}"
                            ) from exc
        except UnicodeDecodeError as exc:
            raise ArtifactContractDiffError(
                f"text artifact is not valid UTF-8: {relative_path}"
            ) from exc
        except OSError as exc:
            raise ArtifactContractDiffError(
                f"cannot read artifact: {relative_path}"
            ) from exc

    return _summarize_records(
        records(),
        container="jsonl",
        relative_path=relative_path,
        run_manifest=None,
    )


def _summarize_records(
    records: Iterable[object],
    *,
    container: str,
    relative_path: str,
    run_manifest: Mapping[str, Any] | None,
) -> dict[str, Any]:
    record_count = 0
    top_level_keys: set[str] = set()
    schema_markers: dict[str, set[str]] = {}
    for record in records:
        record_count += 1
        if not isinstance(record, Mapping):
            continue
        for key in record:
            if not _is_safe_metadata_string(key):
                raise ArtifactContractDiffError(
                    f"structured artifact has an unsafe top-level key: {relative_path}"
                )
            top_level_keys.add(key)
        if len(top_level_keys) > MAX_STRUCTURAL_ITEMS:
            raise ArtifactContractDiffError(
                f"structured artifact has too many top-level keys: {relative_path}"
            )
        _collect_schema_versions(record, schema_markers, relative_path)

    summary: dict[str, Any] = {
        "container": container,
        "record_count": record_count,
        "top_level_keys": sorted(top_level_keys),
    }
    if schema_markers:
        summary["schema_versions"] = {
            field: sorted(values) for field, values in sorted(schema_markers.items())
        }
    if run_manifest is not None:
        digests = _validated_run_manifest_digests(run_manifest, relative_path)
        if digests:
            summary["run_manifest_digests"] = digests
    return summary


def _collect_schema_versions(
    record: Mapping[str, Any],
    markers: dict[str, set[str]],
    relative_path: str,
) -> None:
    for field in ("$id", "$schema", "schema_id", "schema_version"):
        value = record.get(field)
        if isinstance(value, str):
            _add_schema_marker(markers, field, value, relative_path)
    artifact_versions = record.get("artifact_schema_versions")
    if isinstance(artifact_versions, Mapping):
        for field, value in artifact_versions.items():
            if isinstance(field, str) and isinstance(value, str):
                _add_schema_marker(
                    markers,
                    f"artifact_schema_versions.{field}",
                    value,
                    relative_path,
                )


def _add_schema_marker(
    markers: dict[str, set[str]],
    field: str,
    value: str,
    relative_path: str,
) -> None:
    if not _is_safe_metadata_string(field) or not _is_safe_metadata_string(value):
        raise ArtifactContractDiffError(
            f"structured artifact schema marker is unsafe: {relative_path}"
        )
    markers.setdefault(field, set()).add(value)
    if sum(len(values) for values in markers.values()) > MAX_STRUCTURAL_ITEMS:
        raise ArtifactContractDiffError(
            f"structured artifact has too many schema markers: {relative_path}"
        )


def _is_safe_metadata_string(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= MAX_METADATA_STRING_LENGTH
        and not any(ord(character) < 32 for character in value)
        and _LOCAL_ABSOLUTE_PATH_PATTERN.match(value) is None
        and not value.lower().startswith("file:")
    )


def _validated_run_manifest_digests(
    value: Mapping[str, Any], relative_path: str
) -> dict[str, Any]:
    digests: dict[str, Any] = {}
    for field in RUN_MANIFEST_DIGEST_FIELDS:
        if field not in value:
            continue
        candidate = value[field]
        if field in {"input_digest", "config_digest"}:
            if not isinstance(candidate, str) or _DIGEST_PATTERN.fullmatch(candidate) is None:
                raise ArtifactContractDiffError(
                    f"invalid run-manifest digest field in {relative_path}"
                )
            digests[field] = candidate
            continue
        if not isinstance(candidate, Mapping) or len(candidate) > MAX_DIGEST_ENTRIES:
            raise ArtifactContractDiffError(
                f"invalid run-manifest digest field in {relative_path}"
            )
        validated_map: dict[str, str] = {}
        for digest_path, digest_value in candidate.items():
            if (
                not _is_valid_relative_path(digest_path)
                or not isinstance(digest_value, str)
                or _DIGEST_PATTERN.fullmatch(digest_value) is None
            ):
                raise ArtifactContractDiffError(
                    f"invalid run-manifest digest field in {relative_path}"
                )
            validated_map[digest_path] = digest_value
        digests[field] = dict(sorted(validated_map.items()))
    return digests


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
) -> tuple[ChangeReason, ...]:
    reasons: list[ChangeReason] = ["content-changed"]
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
