"""Offline contract for the pinned public process-evidence producer, not a detector verdict."""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
import pandas as pd
import pytest
import yaml

from telemetry_lab.cli import main
from telemetry_lab.features import compute_window_features
from telemetry_lab.io import load_alert_table, load_config, load_events, load_feature_table
from telemetry_lab.preprocess import normalize_events
from telemetry_lab.rules import apply_rules
from telemetry_lab.windowing import build_windows

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/process_evidence/telemetry_events.jsonl"
EXPECTED_DIGEST = "1977b98518497c9a07da6393499cb49e6d0be9140ac5bcd708c2a1cd31a3ad51"
FEATURES = dict(event_count=7, error_count=0, error_rate=0.0, unique_sources=4,
                unique_targets=7, high_severity_count=0, login_fail_count=0,
                login_success_count=0, config_change_count=0, malware_alert_count=0,
                policy_denied_count=0)


def records():
    return [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]


def write_records(tmp_path, rows):
    path = tmp_path / "telemetry_events.jsonl"
    path.write_text("".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
                    encoding="utf-8", newline="\n")
    return path


def pipeline(path):
    cfg = load_config(ROOT / "configs/default.yaml")
    loaded = load_events(path)
    normalized = normalize_events(loaded, error_statuses=cfg["features"]["error_statuses"],
                                  high_severity_levels=cfg["features"]["severity_levels"])
    windows = build_windows(normalized, **cfg["time"])
    features = compute_window_features(normalized, windows, cfg["features"]["count_event_types"])
    return loaded, normalized, features, apply_rules(features, cfg["rules"])


def run_cli(tmp_path, data):
    tmp_path.mkdir(parents=True, exist_ok=True)
    input_path = tmp_path / "telemetry_events.jsonl"
    input_path.write_bytes(data)
    cfg = load_config(ROOT / "configs/default.yaml")
    cfg.update(input_path=str(input_path), output_dir=str(tmp_path / "output"))
    config_path = tmp_path / "integration.yaml"
    config_path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8", newline="\n")
    main(["run", "window", "--config", str(config_path)])
    summary = json.loads((tmp_path / "output/summary.json").read_text(encoding="utf-8"))
    manifest = json.loads((tmp_path / "output/run_manifest.json").read_text(encoding="utf-8"))
    return summary, manifest, input_path, config_path


def legacy_digest(path):
    normalized = path.read_bytes().decode("utf-8").replace("\r\n", "\n").replace("\r", "\n").encode()
    return "sha256:" + sha256(path.name.encode() + b"\0" + normalized + b"\0").hexdigest()


def test_pinned_fixture_and_normalized_observation_contract():
    provenance = json.loads(FIXTURE.with_name("provenance.json").read_text(encoding="utf-8"))
    assert provenance["commit"] == "1d31d4287036cf2bbd3aeb8059d7d332bedef598"
    assert provenance["sha256"] == sha256(FIXTURE.read_bytes()).hexdigest() == EXPECTED_DIGEST
    assert provenance["bytes"] == len(FIXTURE.read_bytes()) == 4108
    expected = records()
    assert all({"timestamp", "event_type", "source", "target", "status"} <= row.keys() for row in expected)
    loaded, normalized, features, alerts = pipeline(FIXTURE)
    assert len(loaded) == len(normalized) == 7
    assert Counter(zip(normalized.event_type, normalized.status)) == {
        ("process_added", "added"): 1, ("process_removed", "removed"): 1,
        ("process_modified", "modified"): 1, ("socket_link_added", "added"): 2,
        ("socket_link_removed", "removed"): 2,
    }
    # Equal timestamps do not establish a tie order. Compare evidence by record identity.
    actual = {row.metadata["record_index"]: row for row in normalized.itertuples()}
    for event in expected:
        row = actual[event["metadata"]["record_index"]]
        assert (row.source, row.target, row.metadata) == (event["source"], event["target"], event["metadata"])
        assert row.source == row.metadata["process_id"]  # same-boot context, not authentication
        assert row.metadata["time_semantics"] == "snapshot_diff_observed_at"
        assert row.metadata["adapter_contract"] == "stacknil.system-evidence.telemetry.v1"
    assert normalized.timestamp.eq(pd.Timestamp("2026-07-05T00:05:00Z")).all()
    assert set(features.columns) == {"window_start", "window_end", *FEATURES}
    assert len(features) == 1 and features.iloc[0][list(FEATURES)].to_dict() == FEATURES
    assert features.iloc[0].window_start == pd.Timestamp("2026-07-05T00:05:00Z")
    assert features.iloc[0].window_end == pd.Timestamp("2026-07-05T00:06:00Z")
    assert alerts.empty


def test_real_cli_outputs_schemas_and_exact_fingerprint_attribution(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # paths and schema lookup must not depend on repository cwd
    summary, manifest, input_path, config_path = run_cli(tmp_path, FIXTURE.read_bytes())
    assert {key: summary[key] for key in ("normalized_event_count", "window_count", "feature_row_count", "alert_count")} == {
        "normalized_event_count": 7, "window_count": 1, "feature_row_count": 1, "alert_count": 0}
    assert summary["triggered_rule_names"] == [] and summary["triggered_rule_counts"] == {}
    names = {Path(path).name for path in summary["generated_artifacts"]}
    assert names == {"features.csv", "alerts.csv", "summary.json", "run_manifest.json",
                     "event_count_timeline.png", "error_rate_timeline.png", "alerts_timeline.png"}
    for artifact, schema in ((summary, "telemetry_summary.schema.json"), (manifest, "run_manifest.v2.schema.json")):
        validator = Draft202012Validator(json.loads((ROOT / "schemas" / schema).read_text(encoding="utf-8")), format_checker=FormatChecker())
        validator.validate(artifact)
    assert manifest["artifact_schema_versions"] == {"run_manifest": "run-manifest/v2", "telemetry_summary": "telemetry-summary/v1"}
    assert manifest["execution_mode"] == "synthetic-local"
    assert manifest["input_file_digests"] == {"external/input/telemetry_events.jsonl": "sha256:" + EXPECTED_DIGEST}
    assert manifest["config_file_digests"] == {"external/config/integration.yaml": "sha256:" + sha256(config_path.read_bytes()).hexdigest()}
    assert manifest["input_digest"] == legacy_digest(input_path)
    assert manifest["config_digest"] == legacy_digest(config_path)
    features = load_feature_table(tmp_path / "output/features.csv")
    assert set(features.columns) == {"window_start", "window_end", *FEATURES}
    assert features.iloc[0][list(FEATURES)].to_dict() == FEATURES
    assert load_alert_table(tmp_path / "output/alerts.csv").empty


@pytest.mark.parametrize("field", ["timestamp", "event_type", "source", "target", "status"])
def test_missing_required_column_is_rejected(tmp_path, field):
    rows = records()
    for row in rows:
        del row[field]
    with pytest.raises(ValueError, match="Missing required event fields"):
        load_events(write_records(tmp_path, rows))


@pytest.mark.parametrize("value", [None, "", "   "])
def test_missing_required_row_value_is_rejected(tmp_path, value):
    rows = records()
    rows[0]["source"] = value
    with pytest.raises(ValueError, match="Missing required event values"):
        load_events(write_records(tmp_path, rows))


def test_malformed_timestamp_fails_normalization_not_structural_loading(tmp_path):
    rows = records()
    rows[0]["timestamp"] = "not-a-timestamp"
    loaded = load_events(write_records(tmp_path, rows))
    assert len(loaded) == 7
    with pytest.raises(ValueError, match="invalid timestamps"):
        normalize_events(loaded)


@pytest.mark.parametrize("line", ['{"timestamp":', "[]"])
def test_bad_jsonl_record_is_rejected_with_line_context(tmp_path, line):
    path = tmp_path / "bad.jsonl"
    path.write_text(FIXTURE.read_text(encoding="utf-8").splitlines()[0] + "\n" + line + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="line 2"):
        load_events(path)


@pytest.mark.parametrize("timestamp,seconds", [("2026-07-05T00:05:10Z", 10), ("2026-07-05T08:05:00+08:00", 0)])
def test_comparison_timestamp_controls_windows_as_an_instant(tmp_path, timestamp, seconds):
    rows = records()
    for row in rows:
        row["timestamp"] = timestamp
    _, normalized, actual, alerts = pipeline(write_records(tmp_path, rows))
    expected = pipeline(FIXTURE)[2].copy()
    for column in ("window_start", "window_end"):
        expected[column] += pd.Timedelta(seconds=seconds)
    pd.testing.assert_frame_equal(actual, expected)
    assert all(meta["time_semantics"] == "snapshot_diff_observed_at" for meta in normalized.metadata)
    assert alerts.empty


def test_unknown_category_and_numeric_identifier_are_transparently_processed(tmp_path):
    rows = records()
    rows[0].update(event_type="future_process_category", source=42)
    _, normalized, features, alerts = pipeline(write_records(tmp_path, rows))
    assert "future_process_category" in set(normalized.event_type) and "42" in set(normalized.source)
    assert features.iloc[0].event_count == 7 and alerts.empty
    assert features.iloc[0][[key for key in FEATURES if key.endswith("_count") and key != "event_count"]].eq(0).all()


@pytest.mark.parametrize("count,alerts_expected", [(2, 0), (3, 1)])
def test_status_change_crosses_unchanged_default_error_threshold(tmp_path, count, alerts_expected):
    rows = records()
    for row in rows[:count]:
        row["status"] = " FAIL "
    _, _, features, alerts = pipeline(write_records(tmp_path, rows))
    assert features.iloc[0].error_count == count
    assert features.iloc[0].error_rate == pytest.approx(count / 7)
    assert len(alerts) == alerts_expected
    assert set(alerts.rule_name) == ({"high_error_rate"} if alerts_expected else set())


@pytest.mark.parametrize("marker", [None, "claimed_occurrence_time"])
def test_time_marker_is_advisory_metadata_not_semantic_admission(tmp_path, marker):
    rows = records()
    for row in rows:
        if marker is None:
            del row["metadata"]["time_semantics"]
        else:
            row["metadata"]["time_semantics"] = marker
    _, normalized, features, alerts = pipeline(write_records(tmp_path, rows))
    pd.testing.assert_frame_equal(features, pipeline(FIXTURE)[2])
    assert [meta.get("time_semantics") for meta in normalized.metadata] == [marker] * 7
    assert alerts.empty


def test_optional_metadata_absence_and_duplicate_timestamp_order(tmp_path):
    rows = list(reversed(records()))
    for row in rows:
        del row["metadata"]
    _, normalized, features, _ = pipeline(write_records(tmp_path, rows))
    assert normalized.metadata.isna().all()
    pd.testing.assert_frame_equal(features, pipeline(FIXTURE)[2])
    rows.append(rows[0].copy())
    _, normalized, features, _ = pipeline(write_records(tmp_path, rows))
    assert len(normalized) == features.iloc[0].event_count == 8
    assert features.iloc[0].unique_sources == 4 and features.iloc[0].unique_targets == 7


def test_windows_are_half_open_around_the_observation_boundary(tmp_path):
    rows = records()
    for timestamp in ("2026-07-05T00:04:59Z", "2026-07-05T00:06:00Z", "2026-07-05T00:06:01Z"):
        rows.append(dict(rows[0], timestamp=timestamp))
    _, _, features, _ = pipeline(write_records(tmp_path, rows))
    counts = features.set_index("window_start").event_count
    assert len(features) == 8
    assert counts[pd.Timestamp("2026-07-05T00:04:50Z")] == 8
    assert counts[pd.Timestamp("2026-07-05T00:05:00Z")] == 7
    assert counts[pd.Timestamp("2026-07-05T00:06:00Z")] == 2


def test_line_endings_change_exact_input_fingerprint_not_legacy_or_semantics(tmp_path):
    data = FIXTURE.read_bytes()
    one = run_cli(tmp_path / "one", data)
    two = run_cli(tmp_path / "two", data.replace(b"\n", b"\r\n"))
    assert one[1]["input_digest"] == two[1]["input_digest"]
    for summary, manifest, input_path, config_path in (one, two):
        assert summary["normalized_event_count"] == 7 and summary["alert_count"] == 0
        assert manifest["input_file_digests"] == {"external/input/telemetry_events.jsonl": "sha256:" + sha256(input_path.read_bytes()).hexdigest()}
        assert manifest["config_file_digests"] == {"external/config/integration.yaml": "sha256:" + sha256(config_path.read_bytes()).hexdigest()}
        assert manifest["config_digest"] == legacy_digest(config_path)
    assert one[1]["input_file_digests"] != two[1]["input_file_digests"]
    pd.testing.assert_frame_equal(load_feature_table(tmp_path / "one/output/features.csv"), load_feature_table(tmp_path / "two/output/features.csv"))
