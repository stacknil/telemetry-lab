from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class GateStep:
    name: str
    command: tuple[str, ...]


def build_gate_steps(python_executable: str) -> list[GateStep]:
    return [
        GateStep(
            name="artifact regeneration",
            command=(python_executable, "scripts/regenerate_artifacts.py", "--check"),
        ),
        GateStep(
            name="schema validation",
            command=(
                python_executable,
                "-m",
                "pytest",
                "tests/test_evidence_pipeline_schemas.py",
            ),
        ),
        GateStep(
            name="full test suite",
            command=(python_executable, "-m", "pytest"),
        ),
    ]


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    steps = build_gate_steps(args.python)

    print("telemetry-lab release contract gate", flush=True)
    print("Scope: local reviewer contract reproduction; not a production SIEM gate.", flush=True)
    print("", flush=True)

    for index, step in enumerate(steps, start=1):
        display_command = " ".join(step.command)
        print(f"[{index}/{len(steps)}] {step.name}", flush=True)
        print(f"$ {display_command}", flush=True)
        result = subprocess.run(step.command, cwd=REPO_ROOT, check=False)
        if result.returncode != 0:
            print("", flush=True)
            print(f"[FAIL] {step.name} failed with exit code {result.returncode}.", flush=True)
            print("The release contract gate stops at the first failing step.", flush=True)
            return result.returncode
        print(f"[OK] {step.name}", flush=True)
        print("", flush=True)

    print("[OK] Release contract gate passed.", flush=True)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the reviewer-facing release contract gate: artifact "
            "regeneration, schema validation, and the full test suite."
        ),
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable used for all gate commands. Defaults to this interpreter.",
    )
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
