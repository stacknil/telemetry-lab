from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
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
) -> dict[str, Any]:
    return {
        "tool_version": __version__,
        "demo_id": demo_id,
        "input_digest": digest_files(input_files),
        "config_digest": digest_files(config_files),
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


def _read_digest_bytes(file_path: Path) -> bytes:
    payload = file_path.read_bytes()
    if file_path.suffix.lower() not in TEXT_DIGEST_SUFFIXES:
        return payload
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
