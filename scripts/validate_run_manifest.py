from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from telemetry_lab.run_manifest_contract import (  # noqa: E402
    RunManifestSchemaSelection,
    RunManifestVersionError,
    select_run_manifest_schema,
)


class RunManifestValidationError(ValueError):
    """Raised when a selected run-manifest schema rejects the document."""


def validate_run_manifest(manifest_path: Path) -> RunManifestSchemaSelection:
    """Load, route, and validate one run manifest from a repository checkout."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    selection = select_run_manifest_schema(manifest)
    schema = json.loads(
        (REPO_ROOT / selection.schema_path).read_text(encoding="utf-8")
    )

    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(
        validator.iter_errors(manifest),
        key=lambda error: [str(part) for part in error.absolute_path],
    )
    if errors:
        summary = "\n".join(_format_error(error) for error in errors[:5])
        raise RunManifestValidationError(
            f"manifest does not satisfy {selection.schema_version} "
            f"({selection.schema_path.as_posix()}):\n{summary}"
        )

    return selection


def _format_error(error: ValidationError) -> str:
    path = ".".join(str(part) for part in error.absolute_path) or "<root>"
    return f"{path}: {error.message}"


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    manifest_path = Path(args.manifest)

    try:
        selection = validate_run_manifest(manifest_path)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        RunManifestVersionError,
        RunManifestValidationError,
        SchemaError,
    ) as exc:
        print(f"[FAIL] {manifest_path}: {exc}", file=sys.stderr)
        return 1

    print(
        f"[OK] {manifest_path}: {selection.schema_version} -> "
        f"{selection.schema_path.as_posix()}"
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Select the exact supported run-manifest schema from its embedded "
            "version marker and validate the document without fallback."
        )
    )
    parser.add_argument("manifest", help="Path to one run_manifest.json document.")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
