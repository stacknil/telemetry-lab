from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_release_contract.py"


def _load_release_contract_script():
    spec = importlib.util.spec_from_file_location(
        "check_release_contract",
        SCRIPT_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_release_contract_gate_runs_expected_steps_with_configured_python(monkeypatch) -> None:
    script = _load_release_contract_script()
    calls: list[tuple[str, ...]] = []

    def fake_run(command, cwd, check):
        calls.append(tuple(command))
        assert cwd == REPO_ROOT
        assert check is False
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    exit_code = script.main(["--python", "python"])

    assert exit_code == 0
    assert calls == [
        ("python", "scripts/regenerate_artifacts.py", "--check"),
        ("python", "-m", "pytest", "tests/test_evidence_pipeline_schemas.py"),
        ("python", "-m", "pytest"),
    ]


def test_release_contract_gate_stops_at_first_failure(monkeypatch, capsys) -> None:
    script = _load_release_contract_script()
    calls: list[tuple[str, ...]] = []

    def fake_run(command, cwd, check):
        calls.append(tuple(command))
        return SimpleNamespace(returncode=7)

    monkeypatch.setattr(subprocess, "run", fake_run)

    exit_code = script.main(["--python", "python"])

    assert exit_code == 7
    assert calls == [("python", "scripts/regenerate_artifacts.py", "--check")]
    assert "[FAIL] artifact regeneration failed with exit code 7." in capsys.readouterr().out
