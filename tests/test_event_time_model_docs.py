from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_repo_file(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_event_time_model_documents_time_field_boundaries() -> None:
    doc = _read_repo_file("docs/event-time-model.md")
    readme = _read_repo_file("README.md")
    docs_index = _read_repo_file("docs/README.md")

    for term in [
        "event_time",
        "observed_time",
        "window_start",
        "window_end",
        "artifact_generated_at",
    ]:
        assert term in doc

    assert "OpenTelemetry Logs Data Model" in doc
    assert "Timestamp" in doc
    assert "ObservedTimestamp" in doc
    assert "source `eventTime` into `event_time`" in doc
    assert "source `observedTime` as `observed_time`" in doc
    assert "[window_start, window_end)" in doc
    assert "must not be used as event evidence" in doc
    assert "(docs/event-time-model.md)" in readme
    assert "(event-time-model.md)" in docs_index
