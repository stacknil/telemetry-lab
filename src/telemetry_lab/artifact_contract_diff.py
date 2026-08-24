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
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO, Final, Literal, TypeAlias


TEXT_ARTIFACT_SUFFIXES: Final = frozenset(
    {".csv", ".json", ".jsonl", ".md", ".txt"}
)
MAX_FILES: Final = 10_000
MAX_STRUCTURED_BYTES: Final = 64 * 1024 * 1024
MAX_STRUCTURE_ITEMS: Final = 4_096
MAX_DIGEST_ENTRIES: Final = 10_000
CHUNK_SIZE: Final = 64 * 1024
RUN_MANIFEST_DIGEST_FIELDS: Final = (
    "input_digest",
    "config_digest",
    "input_file_digests",
    "config_file_digests",
)

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

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_RELATIVE_PATH = re.compile(
    r"^(?![A-Za-z]:)(?!.*\\)(?!.*(?:^|/)\.\.?(?:/|$))[^/]+(?:/[^/]+)*$"
)
_LOCAL_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/)")

_ALLOWED_CHANGE_REASONS = frozenset(
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
    """Raised when an artifact comparison cannot produce a safe result."""


@dataclass(frozen=True)
class ArtifactSnapshot:
    comparison_digest: str
    comparison_size_bytes: int
    structure: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if _DIGEST.fullmatch(self.comparison_digest) is None:
            raise ArtifactContractDiffError("invalid comparison digest")
        if self.comparison_size_bytes < 0:
            raise ArtifactContractDiffError("invalid comparison size")


@dataclass(frozen=True)
class ArtifactDifference:
    path: str
    status: DifferenceStatus
    artifact_kind: ArtifactKind
    change_reasons: tuple[ChangeReason, ...]
    expected: ArtifactSnapshot | None = None
    actual: ArtifactSnapshot | None = None

    def __post_init__(self) -> None:
        if not _safe_relative_path(self.path):
            raise ArtifactContractDiffError("difference path is unsafe")
        if self.artifact_kind not in {"json", "jsonl", "text", "binary"}:
            raise ArtifactContractDiffError("difference artifact kind is invalid")
        if len(set(self.change_reasons)) != len(self.change_reasons):
            raise ArtifactContractDiffError("difference reasons must be unique")
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
                bool(self.change_reasons)
                and self.change_reasons[0] == "content-changed"
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
        status_counts = Counter(item.status for item in self.differences)
        expected_parts = (
            self.unchanged_files
            + self.missing_files
            + self.changed_files
            + len(self.presence_only_paths)
        )
        actual_parts = (
            self.unchanged_files
            + self.extra_files
            + self.changed_files
            + len(self.presence_only_paths)
        )
        if min(
            self.expected_files,
            self.actual_files,
            self.unchanged_files,
            self.missing_files,
            self.extra_files,
            self.changed_files,
        ) < 0:
            raise ArtifactContractDiffError("report counts must be non-negative")
        if self.expected_files > MAX_FILES or self.actual_files > MAX_FILES:
            raise ArtifactContractDiffError("report exceeds the file limit")
        if self.expected_files != expected_parts or self.actual_files != actual_parts:
            raise ArtifactContractDiffError("report file counts are inconsistent")
        if status_counts != Counter(
            missing=self.missing_files,
            extra=self.extra_files,
            changed=self.changed_files,
        ):
            raise ArtifactContractDiffError("report difference counts are inconsistent")
        difference_paths = tuple(item.path for item in self.differences)
        if difference_paths != tuple(sorted(set(difference_paths))):
            raise ArtifactContractDiffError("difference paths must be sorted and unique")
        if self.presence_only_paths != tuple(sorted(set(self.presence_only_paths))):
            raise ArtifactContractDiffError("presence-only paths must be sorted and unique")
        if set(difference_paths) & set(self.presence_only_paths):
            raise ArtifactContractDiffError("difference and presence-only paths overlap")

    @property
    def has_differences(self) -> bool:
        return bool(self.differences)


def normalize_artifact_text_bytes(content: bytes) -> bytes:
    """Validate UTF-8 and canonicalize CRLF or lone CR to LF."""
    return b"".join(_normalized_chunks((content,)))


def compare_artifact_trees(
    expected_root: Path,
    actual_root: Path,
) -> ArtifactContractDiffReport:
    """Compare two local artifact roots using stable relative-path identities."""
    expected = _inventory(_root(expected_root, "expected"))
    actual = _inventory(_root(actual_root, "actual"))
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
                    relative_path,
                    "extra",
                    kind,
                    ("extra-in-actual",),
                    actual=_snapshot(actual_path, relative_path, kind),
                )
            )
        elif actual_path is None:
            missing += 1
            differences.append(
                ArtifactDifference(
                    relative_path,
                    "missing",
                    kind,
                    ("missing-from-actual",),
                    expected=_snapshot(expected_path, relative_path, kind),
                )
            )
        elif kind == "binary":
            presence_only.append(relative_path)
        else:
            before = _identity(expected_path, relative_path, kind)
            after = _identity(actual_path, relative_path, kind)
            if (
                before.comparison_digest == after.comparison_digest
                and before.comparison_size_bytes == after.comparison_size_bytes
            ):
                unchanged += 1
                continue
            before = _with_structure(before, expected_path, relative_path, kind)
            after = _with_structure(after, actual_path, relative_path, kind)
            changed += 1
            differences.append(
                ArtifactDifference(
                    relative_path,
                    "changed",
                    kind,
                    _change_reasons(before, after),
                    expected=before,
                    actual=after,
                )
            )

    return ArtifactContractDiffReport(
        len(expected),
        len(actual),
        unchanged,
        missing,
        extra,
        changed,
        tuple(differences),
        tuple(presence_only),
    )


def _root(path: Path, label: str) -> Path:
    try:
        if _link_like(path) or not stat.S_ISDIR(path.lstat().st_mode):
            raise OSError
        return path.resolve(strict=True)
    except OSError as exc:
        raise ArtifactContractDiffError(
            f"{label} root must be an existing non-symlink directory"
        ) from exc


def _inventory(root: Path) -> dict[str, Path]:
    inventory: dict[str, Path] = {}
    try:
        def fail(error: OSError) -> None:
            raise error

        for current, directories, files in os.walk(
            root, followlinks=False, onerror=fail
        ):
            current_path = Path(current)
            directories.sort()
            files.sort()
            for name in directories:
                if _link_like(current_path / name):
                    raise ArtifactContractDiffError("artifact tree contains a symlink")
            for name in files:
                path = current_path / name
                relative = path.relative_to(root).as_posix()
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode) or _link_like(path):
                    raise ArtifactContractDiffError("artifact tree contains a symlink")
                if not stat.S_ISREG(mode):
                    raise ArtifactContractDiffError(
                        f"artifact tree contains a non-regular artifact: {relative}"
                    )
                if not _safe_relative_path(relative):
                    raise ArtifactContractDiffError("artifact tree contains an unsafe path")
                inventory[relative] = path
                if len(inventory) > MAX_FILES:
                    raise ArtifactContractDiffError("artifact tree exceeds the file limit")
    except OSError as exc:
        raise ArtifactContractDiffError("cannot traverse artifact tree") from exc
    return inventory


def _link_like(path: Path) -> bool:
    info = path.lstat()
    reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & reparse_point
    ):
        return True
    junction = getattr(path, "is_junction", None)
    return bool(junction is not None and junction())


def _safe_relative_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 1_024
        and not any(ord(character) < 32 for character in value)
        and _RELATIVE_PATH.fullmatch(value) is not None
    )


def _artifact_kind(relative_path: str) -> ArtifactKind:
    suffix = Path(relative_path).suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix == ".jsonl":
        return "jsonl"
    return "text" if suffix in TEXT_ARTIFACT_SUFFIXES else "binary"


def _snapshot(path: Path | None, relative_path: str, kind: ArtifactKind) -> ArtifactSnapshot:
    if path is None:
        raise ArtifactContractDiffError(f"artifact is unavailable: {relative_path}")
    return _with_structure(_identity(path, relative_path, kind), path, relative_path, kind)


def _identity(path: Path, relative_path: str, kind: ArtifactKind) -> ArtifactSnapshot:
    digest = sha256()
    size = 0
    try:
        with _regular_file(path, relative_path) as handle:
            chunks: Iterable[bytes] = iter(lambda: handle.read(CHUNK_SIZE), b"")
            if kind != "binary":
                chunks = _normalized_chunks(chunks)
            for chunk in chunks:
                digest.update(chunk)
                size += len(chunk)
    except UnicodeDecodeError as exc:
        raise ArtifactContractDiffError(
            f"text artifact is not valid UTF-8: {relative_path}"
        ) from exc
    except OSError as exc:
        raise ArtifactContractDiffError(f"cannot read artifact: {relative_path}") from exc
    return ArtifactSnapshot("sha256:" + digest.hexdigest(), size)


@contextmanager
def _regular_file(path: Path, relative_path: str) -> Iterator[BinaryIO]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
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
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _normalized_chunks(chunks: Iterable[bytes]) -> Iterator[bytes]:
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    pending_cr = False
    for chunk in chunks:
        decoder.decode(chunk, final=False)
        if pending_cr:
            chunk = b"\r" + chunk
            pending_cr = False
        if chunk.endswith(b"\r"):
            chunk = chunk[:-1]
            pending_cr = True
        normalized = chunk.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        if normalized:
            yield normalized
    decoder.decode(b"", final=True)
    if pending_cr:
        yield b"\n"


def _with_structure(
    snapshot: ArtifactSnapshot,
    path: Path,
    relative_path: str,
    kind: ArtifactKind,
) -> ArtifactSnapshot:
    if kind not in {"json", "jsonl"}:
        return snapshot
    if snapshot.comparison_size_bytes > MAX_STRUCTURED_BYTES:
        raise ArtifactContractDiffError(
            f"structured artifact exceeds summary limit: {relative_path}"
        )
    return replace(snapshot, structure=_structure(path, relative_path, kind))


def _structure(path: Path, relative_path: str, kind: ArtifactKind) -> dict[str, Any]:
    text = _structured_text(path, relative_path)
    if kind == "jsonl":
        return _summarize(_jsonl_records(text, relative_path), "jsonl", relative_path)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ArtifactContractDiffError(f"invalid JSON artifact: {relative_path}") from exc
    records = value if isinstance(value, list) else [value]
    manifest = value if isinstance(value, Mapping) else None
    return _summarize(records, _container(value), relative_path, manifest)


def _structured_text(path: Path, relative_path: str) -> str:
    try:
        with _regular_file(path, relative_path) as handle:
            raw = handle.read(2 * MAX_STRUCTURED_BYTES + 1)
        normalized = normalize_artifact_text_bytes(raw)
    except ArtifactContractDiffError:
        raise
    except UnicodeDecodeError as exc:
        raise ArtifactContractDiffError(
            f"text artifact is not valid UTF-8: {relative_path}"
        ) from exc
    except OSError as exc:
        raise ArtifactContractDiffError(f"cannot read artifact: {relative_path}") from exc
    if len(normalized) > MAX_STRUCTURED_BYTES:
        raise ArtifactContractDiffError(
            f"structured artifact exceeds summary limit: {relative_path}"
        )
    return normalized.decode("utf-8")


def _jsonl_records(text: str, relative_path: str) -> Iterator[object]:
    for line_number, line in enumerate(io.StringIO(text), start=1):
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError as exc:
            raise ArtifactContractDiffError(
                f"invalid JSONL artifact: {relative_path}:{line_number}"
            ) from exc


def _summarize(
    records: Iterable[object],
    container: str,
    relative_path: str,
    manifest: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    count = 0
    keys: set[str] = set()
    markers: dict[str, set[str]] = {}
    for record in records:
        count += 1
        if not isinstance(record, Mapping):
            continue
        for key in record:
            if not _safe_metadata(key):
                raise ArtifactContractDiffError(f"unsafe JSON key: {relative_path}")
            keys.add(key)
        for field in ("$id", "$schema", "schema_id", "schema_version"):
            candidate = record.get(field)
            if isinstance(candidate, str):
                _marker(markers, field, candidate, relative_path)
        versions = record.get("artifact_schema_versions")
        if isinstance(versions, Mapping):
            for field, value in versions.items():
                if isinstance(field, str) and isinstance(value, str):
                    _marker(
                        markers,
                        f"artifact_schema_versions.{field}",
                        value,
                        relative_path,
                    )
        if len(keys) > MAX_STRUCTURE_ITEMS:
            raise ArtifactContractDiffError(f"too many JSON keys: {relative_path}")

    summary: dict[str, Any] = {
        "container": container,
        "record_count": count,
        "top_level_keys": sorted(keys),
    }
    if markers:
        summary["schema_versions"] = {
            field: sorted(values) for field, values in sorted(markers.items())
        }
    if manifest is not None:
        digests = _manifest_digests(manifest, relative_path)
        if digests:
            summary["run_manifest_digests"] = digests
    return summary


def _safe_metadata(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= 1_024
        and not any(ord(character) < 32 for character in value)
        and _LOCAL_PATH.match(value) is None
        and not value.lower().startswith("file:")
    )


def _marker(
    markers: dict[str, set[str]], field: str, value: str, relative_path: str
) -> None:
    if not _safe_metadata(field) or not _safe_metadata(value):
        raise ArtifactContractDiffError(f"unsafe schema marker: {relative_path}")
    markers.setdefault(field, set()).add(value)
    if sum(len(values) for values in markers.values()) > MAX_STRUCTURE_ITEMS:
        raise ArtifactContractDiffError(f"too many schema markers: {relative_path}")


def _manifest_digests(value: Mapping[str, Any], relative_path: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in RUN_MANIFEST_DIGEST_FIELDS:
        if field not in value:
            continue
        candidate = value[field]
        if field in {"input_digest", "config_digest"}:
            if not isinstance(candidate, str) or _DIGEST.fullmatch(candidate) is None:
                raise ArtifactContractDiffError(
                    f"invalid run-manifest digest: {relative_path}"
                )
            result[field] = candidate
            continue
        if not isinstance(candidate, Mapping) or len(candidate) > MAX_DIGEST_ENTRIES:
            raise ArtifactContractDiffError(
                f"invalid run-manifest digest map: {relative_path}"
            )
        checked: dict[str, str] = {}
        for item_path, digest in candidate.items():
            if (
                not _safe_relative_path(item_path)
                or not isinstance(digest, str)
                or _DIGEST.fullmatch(digest) is None
            ):
                raise ArtifactContractDiffError(
                    f"invalid run-manifest digest map: {relative_path}"
                )
            checked[item_path] = digest
        result[field] = dict(sorted(checked.items()))
    return result


def _container(value: object) -> str:
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
    before = expected.structure or {}
    after = actual.structure or {}
    structural_fields = ("container", "record_count", "top_level_keys")
    if any(before.get(field) != after.get(field) for field in structural_fields):
        reasons.append("structure-changed")
    if before.get("schema_versions") != after.get("schema_versions"):
        reasons.append("schema-version-changed")
    if before.get("run_manifest_digests") != after.get("run_manifest_digests"):
        reasons.append("run-manifest-digest-changed")
    return tuple(reasons)
