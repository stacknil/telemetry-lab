from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from ..io import ensure_output_directory, ensure_output_file_path
from ..manifest import RUN_MANIFEST_SCHEMA_VERSION, build_run_manifest, write_run_manifest
from ..time_utils import parse_utc_timestamp

CLOUDTRAIL_REQUIRED_FIELDS = (
    "eventTime",
    "userIdentity",
    "eventSource",
    "eventName",
    "awsRegion",
    "sourceIPAddress",
    "userAgent",
    "errorCode",
    "requestParameters",
    "responseElements",
    "eventID",
)
REQUIRED_RULE_IDS = (
    "failed_console_login_burst",
    "new_access_key_creation_after_failed_logins",
    "policy_attachment_after_unusual_source_ip",
    "cloudtrail_logging_disabled_near_iam_change",
    "security_group_ingress_opened_after_identity_change",
)
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CLOUD_IAM_CONFIG_FIELDS = frozenset(
    (
        "input_path",
        "artifacts_dir",
        "expected_source_ips",
        "attack_mappings",
        "rules",
    )
)
CLOUD_IAM_ATTACK_MAPPING_FIELDS = frozenset(("id", "name", "tactic", "reference"))
CLOUD_IAM_RULE_FIELDS = {
    "failed_console_login_burst": frozenset(
        ("name", "severity", "threshold", "window_minutes", "attack_mapping_ids")
    ),
    "new_access_key_creation_after_failed_logins": frozenset(
        ("name", "severity", "lookback_minutes", "attack_mapping_ids")
    ),
    "policy_attachment_after_unusual_source_ip": frozenset(
        ("name", "severity", "attack_mapping_ids")
    ),
    "cloudtrail_logging_disabled_near_iam_change": frozenset(
        (
            "name",
            "severity",
            "near_window_minutes",
            "identity_change_event_names",
            "attack_mapping_ids",
        )
    ),
    "security_group_ingress_opened_after_identity_change": frozenset(
        (
            "name",
            "severity",
            "follow_on_window_minutes",
            "identity_change_event_names",
            "attack_mapping_ids",
        )
    ),
}


def default_demo_root() -> Path:
    return Path(__file__).resolve().parents[3] / "demos" / "cloud-iam-change-investigation-demo"


def run_demo(
    demo_root: Path | None = None,
    artifacts_dir: Path | None = None,
) -> dict[str, Any]:
    demo_root = Path(demo_root or default_demo_root()).resolve()
    config_path = demo_root / "config" / "investigation.yaml"
    config = validate_demo_config(load_yaml(config_path))
    artifacts_dir = Path(
        artifacts_dir
        or resolve_demo_path(demo_root, str(config["artifacts_dir"]))
    ).resolve()
    ensure_output_directory(artifacts_dir)

    input_path = resolve_demo_path(demo_root, str(config["input_path"]))
    normalized_events = normalize_cloudtrail_events(load_jsonl(input_path))
    signals = evaluate_cloud_iam_signals(normalized_events, config)
    summary = build_investigation_summary(normalized_events, signals, config)
    report_text = build_investigation_report(normalized_events, signals, summary)

    paths = {
        "normalized_cloudtrail_events": write_json(
            normalized_events,
            artifacts_dir / "normalized_cloudtrail_events.json",
        ),
        "investigation_signals": write_json(
            signals,
            artifacts_dir / "investigation_signals.json",
        ),
        "investigation_summary": write_json(
            summary,
            artifacts_dir / "investigation_summary.json",
        ),
        "investigation_report": write_text(
            report_text,
            artifacts_dir / "investigation_report.md",
        ),
    }
    paths["run_manifest"] = write_run_manifest(
        build_run_manifest(
            demo_id="cloud-iam",
            input_files={input_path.relative_to(demo_root).as_posix(): input_path},
            config_files={config_path.relative_to(demo_root).as_posix(): config_path},
            artifact_schema_versions={
                "cloud_iam_findings": "cloud-iam-findings/v1",
                "cloud_iam_summary": "cloud-iam-summary/v1",
                "cloudtrail_normalized_events": "cloudtrail-normalized-events/v1",
                "run_manifest": RUN_MANIFEST_SCHEMA_VERSION,
            },
        ),
        artifacts_dir / "run_manifest.json",
    )

    return {
        "demo_root": demo_root,
        "artifacts_dir": artifacts_dir,
        "raw_event_count": len(normalized_events),
        "signal_count": len(signals),
        "rule_count": len(config["rules"]),
        "artifacts": paths,
    }


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise ValueError("YAML config must deserialize into a mapping.")
    return payload


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at line {line_number} in {path}") from exc
            if not isinstance(payload, dict):
                raise ValueError("Expected JSON object records in JSONL input.")
            records.append(payload)
    return records


def validate_demo_config(config: Mapping[str, Any]) -> dict[str, Any]:
    reject_unknown_fields(config, CLOUD_IAM_CONFIG_FIELDS)

    input_path = require_non_empty_string(config.get("input_path"), "input_path")
    artifacts_dir = require_non_empty_string(
        config.get("artifacts_dir", "artifacts"),
        "artifacts_dir",
    )
    expected_source_ips = require_string_list(
        config.get("expected_source_ips", []),
        "expected_source_ips",
    )

    attack_mappings = config.get("attack_mappings")
    if not isinstance(attack_mappings, Mapping) or not attack_mappings:
        raise ValueError("Config field 'attack_mappings' must be a non-empty mapping.")
    if len(attack_mappings) > 5:
        raise ValueError("Config field 'attack_mappings' must contain at most 5 entries.")
    validated_attack_mappings = {
        str(mapping_id).strip(): validate_attack_mapping(mapping_id, mapping)
        for mapping_id, mapping in attack_mappings.items()
    }

    rules = config.get("rules")
    if not isinstance(rules, Mapping):
        raise ValueError("Config field 'rules' must be a mapping.")
    reject_unknown_fields(rules, set(REQUIRED_RULE_IDS), parent="rules")

    validated_rules: dict[str, dict[str, Any]] = {}
    for rule_id in REQUIRED_RULE_IDS:
        raw_rule = rules.get(rule_id)
        if not isinstance(raw_rule, Mapping):
            raise ValueError(f"Config field 'rules.{rule_id}' must be a mapping.")
        validated_rules[rule_id] = validate_rule_config(
            rule_id,
            raw_rule,
            known_mapping_ids=set(validated_attack_mappings),
        )

    return {
        "input_path": input_path,
        "artifacts_dir": artifacts_dir,
        "expected_source_ips": expected_source_ips,
        "attack_mappings": validated_attack_mappings,
        "rules": validated_rules,
    }


def validate_attack_mapping(mapping_id: object, raw_mapping: object) -> dict[str, str]:
    if not isinstance(raw_mapping, Mapping):
        raise ValueError(f"ATT&CK mapping '{mapping_id}' must be a mapping.")
    reject_unknown_fields(
        raw_mapping,
        CLOUD_IAM_ATTACK_MAPPING_FIELDS,
        parent=f"attack_mappings.{mapping_id}",
    )
    return {
        "id": require_non_empty_string(mapping_id, "attack_mappings.id"),
        "name": require_non_empty_string(raw_mapping.get("name"), f"attack_mappings.{mapping_id}.name"),
        "tactic": require_non_empty_string(
            raw_mapping.get("tactic"),
            f"attack_mappings.{mapping_id}.tactic",
        ),
        "reference": require_non_empty_string(
            raw_mapping.get("reference"),
            f"attack_mappings.{mapping_id}.reference",
        ),
    }


def validate_rule_config(
    rule_id: str,
    raw_rule: Mapping[str, Any],
    *,
    known_mapping_ids: set[str],
) -> dict[str, Any]:
    reject_unknown_fields(
        raw_rule,
        CLOUD_IAM_RULE_FIELDS[rule_id],
        parent=f"rules.{rule_id}",
    )
    name = require_non_empty_string(raw_rule.get("name"), f"rules.{rule_id}.name")
    severity = require_non_empty_string(raw_rule.get("severity"), f"rules.{rule_id}.severity")
    severity = severity.lower()
    if severity not in SEVERITY_ORDER:
        raise ValueError(f"Rule '{rule_id}' uses unsupported severity '{severity}'.")
    attack_mapping_ids = require_string_list(
        raw_rule.get("attack_mapping_ids"),
        f"rules.{rule_id}.attack_mapping_ids",
    )
    unknown_mapping_ids = sorted(set(attack_mapping_ids) - known_mapping_ids)
    if unknown_mapping_ids:
        raise ValueError(
            f"Rule '{rule_id}' references unknown ATT&CK mapping IDs: "
            + ", ".join(unknown_mapping_ids)
        )

    rule = {
        "name": name,
        "severity": severity,
        "attack_mapping_ids": attack_mapping_ids,
    }
    for field in (
        "threshold",
        "window_minutes",
        "lookback_minutes",
        "near_window_minutes",
        "follow_on_window_minutes",
    ):
        if field in raw_rule:
            rule[field] = require_positive_int(raw_rule[field], f"rules.{rule_id}.{field}")
    if "identity_change_event_names" in raw_rule:
        rule["identity_change_event_names"] = require_string_list(
            raw_rule["identity_change_event_names"],
            f"rules.{rule_id}.identity_change_event_names",
        )
    return rule


def normalize_cloudtrail_events(raw_events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for index, raw_event in enumerate(raw_events, start=1):
        for field in CLOUDTRAIL_REQUIRED_FIELDS:
            if field not in raw_event:
                raise ValueError(f"CloudTrail-like event {index} is missing field '{field}'.")

        event_id = require_non_empty_string(raw_event["eventID"], f"event {index}.eventID")
        if event_id in seen_ids:
            raise ValueError(f"Duplicate eventID found in sample input: {event_id}")
        seen_ids.add(event_id)

        user_identity = raw_event["userIdentity"]
        if not isinstance(user_identity, Mapping):
            raise ValueError(f"CloudTrail-like event {event_id} has non-object userIdentity.")
        request_parameters = raw_event["requestParameters"]
        if not isinstance(request_parameters, Mapping):
            raise ValueError(f"CloudTrail-like event {event_id} has non-object requestParameters.")
        response_elements = raw_event["responseElements"]
        if response_elements is None:
            response_elements = {}
        if not isinstance(response_elements, Mapping):
            raise ValueError(f"CloudTrail-like event {event_id} has non-object responseElements.")

        event_time = parse_timestamp(
            require_non_empty_string(raw_event["eventTime"], f"event {index}.eventTime")
        )
        observed_time = parse_optional_timestamp(
            raw_event.get("observedTime"),
            f"event {index}.observedTime",
        )
        event_source = require_non_empty_string(
            raw_event["eventSource"],
            f"event {index}.eventSource",
        )
        event_name = require_non_empty_string(raw_event["eventName"], f"event {index}.eventName")
        actor = extract_actor(user_identity)

        normalized.append(
            {
                "eventID": event_id,
                "event_time": event_time,
                "observed_time": observed_time,
                "eventTime": event_time,
                "actor": actor,
                "identityType": normalize_optional_text(user_identity.get("type")),
                "eventSource": event_source,
                "eventName": event_name,
                "awsRegion": require_non_empty_string(
                    raw_event["awsRegion"],
                    f"event {index}.awsRegion",
                ),
                "sourceIPAddress": require_non_empty_string(
                    raw_event["sourceIPAddress"],
                    f"event {index}.sourceIPAddress",
                ),
                "userAgent": require_non_empty_string(raw_event["userAgent"], f"event {index}.userAgent"),
                "errorCode": normalize_optional_text(raw_event.get("errorCode")),
                "requestParameters": dict(request_parameters),
                "responseElements": dict(response_elements),
                "userIdentity": dict(user_identity),
                "outcome": classify_outcome(raw_event.get("errorCode"), response_elements),
            }
        )

    return sorted(
        normalized,
        key=lambda event: (format_timestamp(event["event_time"]), event["eventID"]),
    )


def evaluate_cloud_iam_signals(
    events: Sequence[Mapping[str, Any]],
    config: Mapping[str, Any],
) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    rules = config["rules"]

    signals.extend(
        detect_failed_console_login_burst(
            events,
            rules["failed_console_login_burst"],
            config,
        )
    )
    signals.extend(
        detect_access_key_after_failed_logins(
            events,
            rules["new_access_key_creation_after_failed_logins"],
            config,
        )
    )
    signals.extend(
        detect_policy_attachment_after_unusual_source_ip(
            events,
            rules["policy_attachment_after_unusual_source_ip"],
            config,
        )
    )
    signals.extend(
        detect_cloudtrail_logging_disabled_near_iam_change(
            events,
            rules["cloudtrail_logging_disabled_near_iam_change"],
            config,
        )
    )
    signals.extend(
        detect_security_group_ingress_after_identity_change(
            events,
            rules["security_group_ingress_opened_after_identity_change"],
            config,
        )
    )

    signals.sort(
        key=lambda signal: (
            format_timestamp(signal["signal_time"]),
            str(signal["rule_id"]),
            str(signal["actor"]),
        )
    )
    for index, signal in enumerate(signals, start=1):
        signal["signal_id"] = f"CTI-{index:03d}"
    return signals


def detect_failed_console_login_burst(
    events: Sequence[Mapping[str, Any]],
    rule: Mapping[str, Any],
    config: Mapping[str, Any],
) -> list[dict[str, Any]]:
    threshold = int(rule.get("threshold", 3))
    window = timedelta(minutes=int(rule.get("window_minutes", 5)))
    failed_logins = [event for event in events if is_failed_console_login(event)]
    by_actor: dict[str, list[Mapping[str, Any]]] = {}
    for event in failed_logins:
        by_actor.setdefault(str(event["actor"]), []).append(event)

    signals: list[dict[str, Any]] = []
    for actor, actor_events in sorted(by_actor.items()):
        actor_events = sorted(
            actor_events,
            key=lambda event: (format_timestamp(event["event_time"]), str(event["eventID"])),
        )
        for index, event in enumerate(actor_events):
            window_end = event["event_time"] + window
            burst_events = [
                candidate
                for candidate in actor_events[index:]
                if candidate["event_time"] <= window_end
            ]
            if len(burst_events) < threshold:
                continue
            signals.append(
                build_signal(
                    rule_id="failed_console_login_burst",
                    rule=rule,
                    config=config,
                    signal_time=burst_events[threshold - 1]["event_time"],
                    actor=actor,
                    primary_event=burst_events[threshold - 1],
                    evidence_events=burst_events[:threshold],
                    reason=(
                        f"{threshold} failed ConsoleLogin events for {actor} fell inside "
                        f"a {int(rule.get('window_minutes', 5))} minute window."
                    ),
                )
            )
            break
    return signals


def detect_access_key_after_failed_logins(
    events: Sequence[Mapping[str, Any]],
    rule: Mapping[str, Any],
    config: Mapping[str, Any],
) -> list[dict[str, Any]]:
    lookback = timedelta(minutes=int(rule.get("lookback_minutes", 15)))
    failed_logins = [event for event in events if is_failed_console_login(event)]
    signals: list[dict[str, Any]] = []

    for event in events:
        if not is_successful_event(event, event_source="iam.amazonaws.com", event_name="CreateAccessKey"):
            continue
        target_actor = target_identity_name(event) or str(event["actor"])
        window_start = event["event_time"] - lookback
        nearby_failures = [
            login
            for login in failed_logins
            if str(login["actor"]) == target_actor
            and window_start <= login["event_time"] <= event["event_time"]
        ]
        if not nearby_failures:
            continue
        signals.append(
            build_signal(
                rule_id="new_access_key_creation_after_failed_logins",
                rule=rule,
                config=config,
                signal_time=event["event_time"],
                actor=target_actor,
                primary_event=event,
                evidence_events=[*nearby_failures, event],
                reason=(
                    f"CreateAccessKey for {target_actor} occurred after "
                    f"{len(nearby_failures)} failed console login event(s) inside "
                    f"{int(rule.get('lookback_minutes', 15))} minutes."
                ),
            )
        )
    return signals


def detect_policy_attachment_after_unusual_source_ip(
    events: Sequence[Mapping[str, Any]],
    rule: Mapping[str, Any],
    config: Mapping[str, Any],
) -> list[dict[str, Any]]:
    expected_source_ips = set(config.get("expected_source_ips", []))
    policy_events = {"AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy"}
    signals: list[dict[str, Any]] = []

    for event in events:
        if not is_successful_event(event, event_source="iam.amazonaws.com"):
            continue
        if str(event["eventName"]) not in policy_events:
            continue
        source_ip = str(event["sourceIPAddress"])
        if source_ip in expected_source_ips:
            continue
        signals.append(
            build_signal(
                rule_id="policy_attachment_after_unusual_source_ip",
                rule=rule,
                config=config,
                signal_time=event["event_time"],
                actor=str(event["actor"]),
                primary_event=event,
                evidence_events=[event],
                reason=(
                    f"{event['eventName']} came from {source_ip}, which is not in the "
                    "demo's expected source IP list."
                ),
            )
        )
    return signals


def detect_cloudtrail_logging_disabled_near_iam_change(
    events: Sequence[Mapping[str, Any]],
    rule: Mapping[str, Any],
    config: Mapping[str, Any],
) -> list[dict[str, Any]]:
    near_window = timedelta(minutes=int(rule.get("near_window_minutes", 10)))
    identity_change_names = set(
        rule.get(
            "identity_change_event_names",
            ["CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy"],
        )
    )
    disable_events = {"StopLogging", "DeleteTrail", "UpdateTrail"}
    iam_changes = [
        event
        for event in events
        if is_successful_event(event, event_source="iam.amazonaws.com")
        and str(event["eventName"]) in identity_change_names
    ]
    signals: list[dict[str, Any]] = []

    for event in events:
        if not is_successful_event(event, event_source="cloudtrail.amazonaws.com"):
            continue
        if str(event["eventName"]) not in disable_events:
            continue
        nearby_changes = [
            change
            for change in iam_changes
            if abs(event["event_time"] - change["event_time"]) <= near_window
        ]
        if not nearby_changes:
            continue
        signals.append(
            build_signal(
                rule_id="cloudtrail_logging_disabled_near_iam_change",
                rule=rule,
                config=config,
                signal_time=event["event_time"],
                actor=str(event["actor"]),
                primary_event=event,
                evidence_events=[*nearby_changes, event],
                reason=(
                    f"{event['eventName']} occurred within "
                    f"{int(rule.get('near_window_minutes', 10))} minutes of "
                    f"{len(nearby_changes)} IAM change event(s)."
                ),
            )
        )
    return signals


def detect_security_group_ingress_after_identity_change(
    events: Sequence[Mapping[str, Any]],
    rule: Mapping[str, Any],
    config: Mapping[str, Any],
) -> list[dict[str, Any]]:
    follow_on_window = timedelta(minutes=int(rule.get("follow_on_window_minutes", 15)))
    identity_change_names = set(
        rule.get(
            "identity_change_event_names",
            ["CreateAccessKey", "AttachUserPolicy", "AttachRolePolicy"],
        )
    )
    identity_changes = [
        event
        for event in events
        if is_successful_event(event, event_source="iam.amazonaws.com")
        and str(event["eventName"]) in identity_change_names
    ]
    signals: list[dict[str, Any]] = []

    for event in events:
        if not is_successful_event(
            event,
            event_source="ec2.amazonaws.com",
            event_name="AuthorizeSecurityGroupIngress",
        ):
            continue
        if not opens_ingress_to_world(event):
            continue
        window_start = event["event_time"] - follow_on_window
        nearby_changes = [
            change
            for change in identity_changes
            if window_start <= change["event_time"] <= event["event_time"]
        ]
        if not nearby_changes:
            continue
        signals.append(
            build_signal(
                rule_id="security_group_ingress_opened_after_identity_change",
                rule=rule,
                config=config,
                signal_time=event["event_time"],
                actor=str(event["actor"]),
                primary_event=event,
                evidence_events=[*nearby_changes, event],
                reason=(
                    "AuthorizeSecurityGroupIngress opened a world-routable range after "
                    f"{len(nearby_changes)} IAM change event(s) inside "
                    f"{int(rule.get('follow_on_window_minutes', 15))} minutes."
                ),
            )
        )
    return signals


def build_signal(
    *,
    rule_id: str,
    rule: Mapping[str, Any],
    config: Mapping[str, Any],
    signal_time: datetime,
    actor: str,
    primary_event: Mapping[str, Any],
    evidence_events: Sequence[Mapping[str, Any]],
    reason: str,
) -> dict[str, Any]:
    attack_mappings = config["attack_mappings"]
    return {
        "signal_id": "",
        "rule_id": rule_id,
        "rule_name": str(rule["name"]),
        "severity": str(rule["severity"]),
        "signal_time": signal_time,
        "actor": actor,
        "primary_event_id": str(primary_event["eventID"]),
        "source_ips": sorted({str(event["sourceIPAddress"]) for event in evidence_events}),
        "evidence_event_ids": [str(event["eventID"]) for event in evidence_events],
        "evidence_events": [compact_event(event) for event in evidence_events],
        "attack_mappings": [
            dict(attack_mappings[mapping_id])
            for mapping_id in rule["attack_mapping_ids"]
        ],
        "bounded_correlation_reason": reason,
        "review_scope": (
            "Synthetic signal for reviewer inspection only; it is not a production "
            "detection claim and does not assert a final incident verdict."
        ),
    }


def build_investigation_summary(
    events: Sequence[Mapping[str, Any]],
    signals: Sequence[Mapping[str, Any]],
    config: Mapping[str, Any],
) -> dict[str, Any]:
    rule_counts: dict[str, int] = {}
    for signal in signals:
        rule_counts[str(signal["rule_id"])] = rule_counts.get(str(signal["rule_id"]), 0) + 1

    return {
        "schema_version": "cloud-iam-change-investigation-demo/v1",
        "source_type": "synthetic CloudTrail-like JSONL",
        "event_count": len(events),
        "signal_count": len(signals),
        "rule_counts": dict(sorted(rule_counts.items())),
        "attack_mapping_count": len(config["attack_mappings"]),
        "time_model": {
            "event_time_source": "eventTime",
            "observed_time_source": "observedTime when present",
            "detection_ordering": "event_time",
            "observed_time_event_count": sum(
                1 for event in events if event.get("observed_time") is not None
            ),
        },
        "boundaries": [
            "Synthetic CloudTrail-like events only",
            "No live AWS account",
            "No real account ID",
            "No production detection claim",
            "No final incident verdict",
        ],
    }


def build_investigation_report(
    events: Sequence[Mapping[str, Any]],
    signals: Sequence[Mapping[str, Any]],
    summary: Mapping[str, Any],
) -> str:
    lines = [
        "# Cloud IAM Change Investigation Demo Report",
        "",
        "This deterministic demo reviews synthetic CloudTrail-like events for bounded IAM and cloud-control-plane signals.",
        "It uses no live AWS account, no real account IDs, no realtime ingestion, and no final incident verdict.",
        "",
        "## Run Summary",
        "",
        f"- source_type: {summary['source_type']}",
        f"- normalized_events: {len(events)}",
        f"- investigation_signals: {len(signals)}",
        f"- attack_mapping_count: {summary['attack_mapping_count']}",
        "- time_model: eventTime is normalized to event_time; optional observedTime "
        "is preserved as observed_time but not used for detection ordering",
        "",
        "## Signals",
        "",
    ]
    if not signals:
        lines.append("No signals were generated from the current sample.")
        return "\n".join(lines).rstrip() + "\n"

    for signal in signals:
        mapping_names = ", ".join(mapping["name"] for mapping in signal["attack_mappings"])
        lines.extend(
            [
                f"### {signal['signal_id']} - {signal['rule_name']}",
                "",
                f"- Severity: {signal['severity']}",
                f"- Actor: {signal['actor']}",
                f"- Primary event: {signal['primary_event_id']}",
                f"- Evidence event IDs: {', '.join(signal['evidence_event_ids'])}",
                f"- ATT&CK mapping: {mapping_names}",
                f"- Bounded reason: {signal['bounded_correlation_reason']}",
                "- Scope: synthetic reviewer signal only; no production claim or final verdict",
                "",
            ]
        )

    lines.extend(
        [
            "## Boundaries",
            "",
            "- Synthetic CloudTrail-like events only",
            "- No live AWS account",
            "- No real account ID",
            "- No production detection claim",
            "- No final incident verdict",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def is_failed_console_login(event: Mapping[str, Any]) -> bool:
    if str(event["eventSource"]) != "signin.amazonaws.com":
        return False
    if str(event["eventName"]) != "ConsoleLogin":
        return False
    response_elements = event.get("responseElements", {})
    console_login = ""
    if isinstance(response_elements, Mapping):
        console_login = str(response_elements.get("ConsoleLogin", ""))
    return str(event.get("outcome")) == "failure" or console_login.lower() == "failure"


def is_successful_event(
    event: Mapping[str, Any],
    *,
    event_source: str,
    event_name: str | None = None,
) -> bool:
    if str(event["eventSource"]) != event_source:
        return False
    if event_name is not None and str(event["eventName"]) != event_name:
        return False
    return str(event.get("outcome")) == "success"


def opens_ingress_to_world(event: Mapping[str, Any]) -> bool:
    parameters = event.get("requestParameters", {})
    if not isinstance(parameters, Mapping):
        return False
    permissions = parameters.get("ipPermissions", [])
    if not isinstance(permissions, Sequence) or isinstance(permissions, (str, bytes)):
        return False

    for permission in permissions:
        if not isinstance(permission, Mapping):
            continue
        for range_key, cidr_key in (("ipRanges", "cidrIp"), ("ipv6Ranges", "cidrIpv6")):
            ranges = permission.get(range_key, [])
            if not isinstance(ranges, Sequence) or isinstance(ranges, (str, bytes)):
                continue
            for ip_range in ranges:
                if not isinstance(ip_range, Mapping):
                    continue
                if ip_range.get(cidr_key) in {"0.0.0.0/0", "::/0"}:
                    return True
    return False


def compact_event(event: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "eventID": str(event["eventID"]),
        "event_time": event["event_time"],
        "observed_time": event.get("observed_time"),
        "eventTime": event["eventTime"],
        "actor": str(event["actor"]),
        "eventSource": str(event["eventSource"]),
        "eventName": str(event["eventName"]),
        "awsRegion": str(event["awsRegion"]),
        "sourceIPAddress": str(event["sourceIPAddress"]),
        "errorCode": event.get("errorCode"),
        "requestParameters": dict(event.get("requestParameters", {})),
    }


def classify_outcome(error_code: object, response_elements: Mapping[str, Any]) -> str:
    if normalize_optional_text(error_code):
        return "failure"
    console_login = str(response_elements.get("ConsoleLogin", ""))
    if console_login.lower() == "failure":
        return "failure"
    return "success"


def extract_actor(user_identity: Mapping[str, Any]) -> str:
    for key in ("userName", "principalId", "arn"):
        value = normalize_optional_text(user_identity.get(key))
        if value:
            return value

    session_context = user_identity.get("sessionContext")
    if isinstance(session_context, Mapping):
        issuer = session_context.get("sessionIssuer")
        if isinstance(issuer, Mapping):
            for key in ("userName", "principalId", "arn"):
                value = normalize_optional_text(issuer.get(key))
                if value:
                    return value
    raise ValueError("CloudTrail-like event userIdentity must identify an actor.")


def target_identity_name(event: Mapping[str, Any]) -> str | None:
    parameters = event.get("requestParameters", {})
    if not isinstance(parameters, Mapping):
        return None
    for key in ("userName", "roleName", "targetUserName"):
        value = normalize_optional_text(parameters.get(key))
        if value:
            return value
    return None


def resolve_demo_path(demo_root: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    return (demo_root / candidate).resolve()


def require_non_empty_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Config field '{field_name}' must be a non-empty string.")
    return value.strip()


def require_string_list(value: object, field_name: str) -> list[str]:
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise ValueError(f"Config field '{field_name}' must be a list of non-empty strings.")
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"Config field '{field_name}' must be a list of non-empty strings.")
        normalized.append(item.strip())
    return normalized


def reject_unknown_fields(
    config: Mapping[str, Any],
    allowed_fields: set[str] | frozenset[str],
    *,
    parent: str | None = None,
) -> None:
    unknown_fields = sorted(str(key) for key in config if key not in allowed_fields)
    if not unknown_fields:
        return

    location = f" under '{parent}'" if parent else ""
    raise ValueError(
        f"Unknown config field(s){location}: " + ", ".join(unknown_fields)
    )


def require_positive_int(value: object, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"Config field '{field_name}' must be a positive integer.")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Config field '{field_name}' must be a positive integer.") from exc
    if parsed <= 0:
        raise ValueError(f"Config field '{field_name}' must be a positive integer.")
    return parsed


def normalize_optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_timestamp(raw_value: str) -> datetime:
    return parse_utc_timestamp(raw_value)


def parse_optional_timestamp(value: object, field_name: str) -> datetime | None:
    raw_value = normalize_optional_text(value)
    if raw_value is None:
        return None
    try:
        return parse_timestamp(raw_value)
    except ValueError as exc:
        raise ValueError(f"Field '{field_name}' must be a UTC timestamp.") from exc


def format_timestamp(value: object) -> str:
    timestamp = value if isinstance(value, datetime) else parse_timestamp(str(value))
    return timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")


def write_json(payload: Any, path: Path) -> Path:
    path = ensure_output_file_path(path)
    path.write_text(
        json.dumps(serialize_record(payload), indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def write_text(content: str, path: Path) -> Path:
    path = ensure_output_file_path(path)
    path.write_text(content, encoding="utf-8", newline="\n")
    return path


def serialize_record(value: Any) -> Any:
    if isinstance(value, datetime):
        return format_timestamp(value)
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, dict):
        return {key: serialize_record(item) for key, item in value.items()}
    if isinstance(value, list):
        return [serialize_record(item) for item in value]
    return value
