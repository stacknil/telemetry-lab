from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from telemetry_lab.manifest import (
    RUN_MANIFEST_SCHEMA_VERSION,
    build_run_manifest,
    digest_file_bytes,
    digest_file_map,
    digest_files,
    repository_relative_file_map,
)


def test_digest_files_canonicalizes_text_line_endings(tmp_path) -> None:
    lf_path = tmp_path / "input.jsonl"
    crlf_path = tmp_path / "input-crlf.jsonl"
    lf_path.write_text('{"event": "one"}\n{"event": "two"}\n', encoding="utf-8", newline="\n")
    crlf_path.write_text(
        '{"event": "one"}\r\n{"event": "two"}\r\n',
        encoding="utf-8",
        newline="",
    )

    assert digest_files({"input": lf_path}) == digest_files({"input": crlf_path})


def test_digest_files_preserves_binary_bytes(tmp_path) -> None:
    first_path = tmp_path / "input.bin"
    second_path = tmp_path / "input-copy.bin"
    first_path.write_bytes(b"one\r\ntwo\n")
    second_path.write_bytes(b"one\ntwo\n")

    assert digest_files({"input": first_path}) != digest_files({"input": second_path})


def test_digest_file_map_hashes_exact_bytes_and_normalizes_paths(tmp_path) -> None:
    repo_root = tmp_path / "repo"
    config_path = repo_root / "configs" / "rules.yaml"
    input_path = repo_root / "data" / "events.jsonl"
    config_path.parent.mkdir(parents=True)
    input_path.parent.mkdir(parents=True)
    config_bytes = b"rules:\r\n  - id: one\r\n"
    input_bytes = b'{"event": "one"}\r\n'
    config_path.write_bytes(config_bytes)
    input_path.write_bytes(input_bytes)

    digests = digest_file_map(
        {
            r"data\events.jsonl": input_path,
            "configs/rules.yaml": config_path,
        }
    )

    assert list(digests) == ["configs/rules.yaml", "data/events.jsonl"]
    assert digests["configs/rules.yaml"] == f"sha256:{sha256(config_bytes).hexdigest()}"
    assert digests["data/events.jsonl"] == f"sha256:{sha256(input_bytes).hexdigest()}"
    assert digest_file_bytes(input_path) != digest_file_bytes(
        _write_bytes(tmp_path / "lf-events.jsonl", b'{"event": "one"}\n')
    )


def test_repository_relative_file_map_is_lexically_ordered(tmp_path) -> None:
    repo_root = tmp_path / "repo"
    first_path = repo_root / "data" / "z.jsonl"
    second_path = repo_root / "data" / "a.jsonl"
    first_path.parent.mkdir(parents=True)
    first_path.write_bytes(b"z\n")
    second_path.write_bytes(b"a\n")

    file_map = repository_relative_file_map(
        [first_path, second_path],
        repository_root=repo_root,
    )

    assert list(file_map) == ["data/a.jsonl", "data/z.jsonl"]
    assert list(digest_file_map(file_map)) == ["data/a.jsonl", "data/z.jsonl"]


def test_per_file_change_is_local_and_aggregate_contract_is_preserved(tmp_path) -> None:
    repo_root = tmp_path / "repo"
    first_path = repo_root / "data" / "first.jsonl"
    second_path = repo_root / "data" / "second.jsonl"
    first_path.parent.mkdir(parents=True)
    first_path.write_bytes(b"first\n")
    second_path.write_bytes(b"second\n")
    aggregate_files = {
        "first.jsonl": first_path,
        "second.jsonl": second_path,
    }
    aggregate_before = digest_files(aggregate_files)

    before = digest_file_map(
        repository_relative_file_map(aggregate_files.values(), repository_root=repo_root)
    )
    manifest = build_run_manifest(
        demo_id="window",
        input_files=aggregate_files,
        config_files={"config.yaml": _write_bytes(tmp_path / "config.yaml", b"rules: {}\n")},
        input_file_paths=repository_relative_file_map(
            aggregate_files.values(),
            repository_root=repo_root,
        ),
        config_file_paths={
            "configs/config.yaml": tmp_path / "config.yaml",
        },
        artifact_schema_versions={"run_manifest": RUN_MANIFEST_SCHEMA_VERSION},
    )

    second_path.write_bytes(b"second changed\n")
    after = digest_file_map(
        repository_relative_file_map(aggregate_files.values(), repository_root=repo_root)
    )

    assert before["data/first.jsonl"] == after["data/first.jsonl"]
    assert before["data/second.jsonl"] != after["data/second.jsonl"]
    assert manifest["input_digest"] == aggregate_before
    assert manifest["input_file_digests"] == before


def test_build_manifest_reuses_one_byte_snapshot_per_file(
    tmp_path,
    monkeypatch,
) -> None:
    input_path = _write_bytes(tmp_path / "input.jsonl", b'{"event": "one"}\r\n')
    config_path = _write_bytes(tmp_path / "config.yaml", b"rules:\r\n  enabled: true\r\n")
    input_files = {"input.jsonl": input_path}
    config_files = {"config.yaml": config_path}
    expected_input_digest = digest_files(input_files)
    expected_config_digest = digest_files(config_files)
    expected_input_file_digest = digest_file_bytes(input_path)
    expected_config_file_digest = digest_file_bytes(config_path)
    original_read_bytes = Path.read_bytes
    read_counts: dict[Path, int] = {}

    def tracked_read_bytes(path: Path) -> bytes:
        resolved_path = path.resolve()
        read_counts[resolved_path] = read_counts.get(resolved_path, 0) + 1
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", tracked_read_bytes)

    manifest = build_run_manifest(
        demo_id="window",
        input_files=input_files,
        config_files=config_files,
        input_file_paths={"data/input.jsonl": input_path},
        config_file_paths={"configs/config.yaml": config_path},
        artifact_schema_versions={"run_manifest": RUN_MANIFEST_SCHEMA_VERSION},
    )

    assert read_counts == {
        input_path.resolve(): 1,
        config_path.resolve(): 1,
    }
    assert manifest["input_digest"] == expected_input_digest
    assert manifest["config_digest"] == expected_config_digest
    assert manifest["input_file_digests"] == {
        "data/input.jsonl": expected_input_file_digest
    }
    assert manifest["config_file_digests"] == {
        "configs/config.yaml": expected_config_file_digest
    }


def test_build_manifest_rejects_mismatched_provenance_files(tmp_path) -> None:
    input_path = _write_bytes(tmp_path / "input.jsonl", b'{"event": "one"}\n')
    other_input_path = _write_bytes(
        tmp_path / "other-input.jsonl",
        b'{"event": "other"}\n',
    )
    config_path = _write_bytes(tmp_path / "config.yaml", b"rules: {}\n")

    with pytest.raises(ValueError, match="must reference the same files"):
        build_run_manifest(
            demo_id="window",
            input_files={"input.jsonl": input_path},
            config_files={"config.yaml": config_path},
            input_file_paths={"data/input.jsonl": other_input_path},
            config_file_paths={"configs/config.yaml": config_path},
            artifact_schema_versions={
                "run_manifest": RUN_MANIFEST_SCHEMA_VERSION
            },
        )


def test_repository_relative_file_map_rejects_files_outside_root(tmp_path) -> None:
    outside_path = _write_bytes(tmp_path / "outside.jsonl", b"outside\n")

    with pytest.raises(ValueError, match="inside repository root"):
        repository_relative_file_map(
            [outside_path],
            repository_root=tmp_path / "repo",
        )


def _write_bytes(path, payload: bytes):
    path.write_bytes(payload)
    return path
