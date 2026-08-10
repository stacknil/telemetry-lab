from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from hashlib import sha256
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from . import __version__
from .io import ensure_output_file_path

EXECUTION_MODE = "synthetic-local"
RUN_MANIFEST_SCHEMA_VERSION = "run-manifest/v1"
TEXT_DIGEST_SUFFIXES = {
    ".csv",
    ".json",
    ".jsonl",
    ".md",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


def build_run_manifest(
    *,
    demo_id: str,
    input_files: Mapping[str, Path],
    config_files: Mapping[str, Path],
    artifact_schema_versions: Mapping[str, str],
    input_file_paths: Mapping[str, Path] | None = None,
    config_file_paths: Mapping[str, Path] | None = None,
) -> dict[str, Any]:
    """Build a manifest with legacy aggregate and per-file provenance digests.

    ``input_files`` and ``config_files`` intentionally remain the inputs to the
    existing aggregate digest contract.  The optional ``*_file_paths`` maps are
    keyed by canonical repository-relative paths and are hashed from exact file
    bytes for per-file provenance.
    """

    input_provenance_files = (
        input_files if input_file_paths is None else input_file_paths
    )
    config_provenance_files = (
        config_files if config_file_paths is None else config_file_paths
    )
    return {
        "tool_version": __version__,
        "demo_id": demo_id,
        "input_digest": digest_files(input_files),
        "config_digest": digest_files(config_files),
        "input_file_digests": digest_file_map(input_provenance_files),
        "config_file_digests": digest_file_map(config_provenance_files),
        "artifact_schema_versions": dict(sorted(artifact_schema_versions.items())),
        "execution_mode": EXECUTION_MODE,
    }


def write_run_manifest(manifest: Mapping[str, Any], path: Path) -> Path:
    output_path = ensure_output_file_path(path)
    output_path.write_text(
        json.dumps(dict(manifest), indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return output_path


def digest_files(files: Mapping[str, Path]) -> str:
    if not files:
        raise ValueError("Run manifest digest requires at least one file.")

    digest = sha256()
    for label, path in sorted(files.items()):
        file_path = Path(path)
        if not file_path.is_file():
            raise FileNotFoundError(f"Run manifest input file not found: {file_path}")
        digest.update(label.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_read_digest_bytes(file_path))
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def digest_file_map(files: Mapping[str, Path]) -> dict[str, str]:
    """Hash each file's exact shipped bytes under canonical relative paths.

    This contract deliberately does not parse or normalize text.  Path keys
    are normalized to POSIX repository-relative form and emitted in lexical
    order so the serialized map is deterministic.
    """

    if not files:
        raise ValueError("Run manifest per-file digest requires at least one file.")

    normalized_files: dict[str, Path] = {}
    for label, path in files.items():
        normalized_label = normalize_repository_relative_path(label)
        if normalized_label in normalized_files:
            raise ValueError(
                f"Duplicate normalized run manifest path: {normalized_label}"
            )
        normalized_files[normalized_label] = _require_manifest_file(path)

    return {
        label: digest_file_bytes(path)
        for label, path in sorted(normalized_files.items())
    }


def digest_file_bytes(path: Path) -> str:
    """Return the SHA-256 digest of a file's exact bytes."""

    file_path = _require_manifest_file(path)
    return f"sha256:{sha256(file_path.read_bytes()).hexdigest()}"


def repository_relative_file_map(
    files: Iterable[Path],
    *,
    repository_root: Path,
) -> dict[str, Path]:
    """Map files to normalized repository-relative paths in lexical order."""

    file_map: dict[str, Path] = {}
    for path in files:
        file_path = _require_manifest_file(path)
        relative_path = repository_relative_path(file_path, repository_root)
        if relative_path in file_map:
            raise ValueError(f"Duplicate repository-relative path: {relative_path}")
        file_map[relative_path] = file_path
    if not file_map:
        raise ValueError("Run manifest per-file digest requires at least one file.")
    return dict(sorted(file_map.items()))


def repository_relative_path(path: Path, repository_root: Path) -> str:
    """Return a normalized POSIX path relative to ``repository_root``."""

    file_path = _require_manifest_file(path).resolve()
    root = Path(repository_root).resolve()
    try:
        relative_path = file_path.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"Run manifest file must be inside repository root: {file_path} "
            f"(root: {root})"
        ) from exc
    return normalize_repository_relative_path(relative_path.as_posix())


def normalize_repository_relative_path(value: str | Path) -> str:
    """Normalize and validate a repository-relative manifest path."""

    raw_value = str(value).replace("\\", "/")
    if not raw_value:
        raise ValueError("Run manifest path must not be empty.")

    posix_path = PurePosixPath(raw_value)
    parts = posix_path.parts
    if posix_path.is_absolute() or (
        parts and len(parts[0]) == 2 and parts[0][1] == ":"
    ):
        raise ValueError(f"Run manifest path must be repository-relative: {value}")
    if any(part == ".." for part in parts):
        raise ValueError(f"Run manifest path must not traverse its root: {value}")

    normalized_parts = [part for part in parts if part not in {"", "."}]
    if not normalized_parts:
        raise ValueError("Run manifest path must not be empty.")
    return "/".join(normalized_parts)


def resolve_manifest_repository_root(path: Path, *, fallback: Path) -> Path:
    """Find the repository root, with a bounded fallback for isolated demos."""

    candidate = Path(path).resolve()
    start = candidate if candidate.is_dir() else candidate.parent
    for parent in (start, *start.parents):
        if (parent / "pyproject.toml").is_file() and (parent / "src").is_dir():
            return parent
    return Path(fallback).resolve()


def _read_digest_bytes(file_path: Path) -> bytes:
    payload = file_path.read_bytes()
    if file_path.suffix.lower() not in TEXT_DIGEST_SUFFIXES:
        return payload
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _require_manifest_file(path: Path) -> Path:
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Run manifest input file not found: {file_path}")
    return file_path
