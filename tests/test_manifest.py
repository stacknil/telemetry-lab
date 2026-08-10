from __future__ import annotations

from hashlib import sha256

import pytest

from telemetry_lab.manifest import (
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
        artifact_schema_versions={"run_manifest": "run-manifest/v1"},
    )

    second_path.write_bytes(b"second changed\n")
    after = digest_file_map(
        repository_relative_file_map(aggregate_files.values(), repository_root=repo_root)
    )

    assert before["data/first.jsonl"] == after["data/first.jsonl"]
    assert before["data/second.jsonl"] != after["data/second.jsonl"]
    assert manifest["input_digest"] == aggregate_before
    assert manifest["input_file_digests"] == before


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
