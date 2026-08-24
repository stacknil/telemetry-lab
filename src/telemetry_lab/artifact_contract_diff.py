from __future__ import annotations

import codecs
import os
import re
import stat
from collections import Counter
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import BinaryIO, Final, Literal, TypeAlias


TEXT_ARTIFACT_SUFFIXES: Final = frozenset(
    {".csv", ".json", ".jsonl", ".md", ".txt"}
)
MAX_FILES: Final = 10_000
CHUNK_SIZE: Final = 64 * 1024

ArtifactKind: TypeAlias = Literal["json", "jsonl", "text", "binary"]
DifferenceStatus: TypeAlias = Literal["missing", "extra", "changed"]
ChangeReason: TypeAlias = Literal[
    "missing-from-actual",
    "extra-in-actual",
    "content-changed",
]

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_RELATIVE_PATH = re.compile(
    r"^(?![A-Za-z]:)(?!.*\\)(?!.*(?:^|/)\.\.?(?:/|$))[^/]+(?:/[^/]+)*$"
)
class ArtifactContractDiffError(ValueError):
    """Raised when an artifact comparison cannot produce a safe result."""


@dataclass(frozen=True)
class ArtifactSnapshot:
    comparison_digest: str
    comparison_size_bytes: int

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
                self.change_reasons == ("content-changed",)
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
            changed += 1
            differences.append(
                ArtifactDifference(
                    relative_path,
                    "changed",
                    kind,
                    ("content-changed",),
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
    return _identity(path, relative_path, kind)


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
