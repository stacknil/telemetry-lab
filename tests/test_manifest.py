from __future__ import annotations

from telemetry_lab.manifest import digest_files


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
