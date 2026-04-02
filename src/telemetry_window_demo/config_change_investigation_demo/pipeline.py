from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CHANGE_REQUIRED_FIELDS = (
    "change_id",
    "timestamp",
    "actor",
    "target_system",
    "config_key",
    "old_value",
    "new_value",
    "change_result",
)
DENIAL_REQUIRED_FIELDS = (
    "denial_id",
    "timestamp",
    "actor",
    "target_system",
    "policy_name",
    "decision",
    "reason",
)
FOLLOW_ON_REQUIRED_FIELDS = (
    "event_id",
    "timestamp",
    "target_system",
    "event_type",
    "details",
)


def default_demo_root() -> Path:
    return Path(__file__).resolve().parents[3] / "demos" / "config-change-investigation-demo"


def run_demo(
    demo_root: Path | None = None,
    artifacts_dir: Path | None = None,
) -> dict[str, Any]:
    demo_root = Path(demo_root or default_demo_root()).resolve()
    config = load_yaml(demo_root / "config" / "investigation.yaml")
    input_paths = config.get("input_paths", {})
    artifacts_dir = Path(
        artifacts_dir
        or resolve_demo_path(demo_root, str(config.get("artifacts_dir", "artifacts")))
    ).resolve()
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    config_changes = normalize_config_changes(
        load_jsonl(resolve_demo_path(demo_root, str(input_paths["config_changes"])))
    )
    policy_denials = normalize_policy_denials(
        load_jsonl(resolve_demo_path(demo_root, str(input_paths["policy_denials"])))
    )
    follow_on_events = normalize_follow_on_events(
        load_jsonl(resolve_demo_path(demo_root, str(input_paths["follow_on_events"])))
    )

    rule_hits = evaluate_risky_config_changes(config_changes, config.get("rules", []))
    investigations = build_investigations(
        rule_hits,
        policy_denials,
        follow_on_events,
        correlation_minutes=int(config.get("correlation_minutes", 15)),
    )
    summary = build_investigation_summary(
        investigations,
        correlation_minutes=int(config.get("correlation_minutes", 15)),
    )
    report_text = build_investigation_report(
        config_changes=config_changes,
        rule_hits=rule_hits,
        investigations=investigations,
        correlation_minutes=int(config.get("correlation_minutes", 15)),
    )

    paths = {
        "change_events_normalized": write_json(
            config_changes,
            artifacts_dir / "change_events_normalized.json",
        ),
        "investigation_hits": write_json(
            investigations,
            artifacts_dir / "investigation_hits.json",
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

    return {
        "demo_root": demo_root,
        "artifacts_dir": artifacts_dir,
        "change_event_count": len(config_changes),
        "risky_change_count": len(rule_hits),
        "investigation_count": len(investigations),
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


def resolve_demo_path(demo_root: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    return (demo_root / candidate).resolve()


def normalize_config_changes(raw_events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw_event in enumerate(raw_events, start=1):
        for field in CHANGE_REQUIRED_FIELDS:
            value = raw_event.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Config change {index} is missing required string field '{field}'."
                )

        change_id = str(raw_event["change_id"]).strip()
        if change_id in seen_ids:
            raise ValueError(f"Duplicate change_id found in sample input: {change_id}")
        seen_ids.add(change_id)

        normalized.append(
            {
                "change_id": change_id,
                "timestamp": parse_timestamp(str(raw_event["timestamp"])),
                "actor": str(raw_event["actor"]).strip(),
                "target_system": str(raw_event["target_system"]).strip(),
                "config_key": str(raw_event["config_key"]).strip(),
                "old_value": str(raw_event["old_value"]).strip(),
                "new_value": str(raw_event["new_value"]).strip(),
                "change_result": str(raw_event["change_result"]).strip().lower(),
                "change_ticket": normalize_optional_text(raw_event.get("change_ticket")),
            }
        )

    return sorted(
        normalized,
        key=lambda event: (format_timestamp(event["timestamp"]), event["change_id"]),
    )


def normalize_policy_denials(raw_events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw_event in enumerate(raw_events, start=1):
        for field in DENIAL_REQUIRED_FIELDS:
            value = raw_event.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Policy denial {index} is missing required string field '{field}'."
                )

        denial_id = str(raw_event["denial_id"]).strip()
        if denial_id in seen_ids:
            raise ValueError(f"Duplicate denial_id found in sample input: {denial_id}")
        seen_ids.add(denial_id)

        normalized.append(
            {
                "denial_id": denial_id,
                "timestamp": parse_timestamp(str(raw_event["timestamp"])),
                "actor": str(raw_event["actor"]).strip(),
                "target_system": str(raw_event["target_system"]).strip(),
                "policy_name": str(raw_event["policy_name"]).strip(),
                "decision": str(raw_event["decision"]).strip().lower(),
                "reason": str(raw_event["reason"]).strip(),
            }
        )

    return sorted(
        normalized,
        key=lambda event: (format_timestamp(event["timestamp"]), event["denial_id"]),
    )


def normalize_follow_on_events(raw_events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw_event in enumerate(raw_events, start=1):
        for field in FOLLOW_ON_REQUIRED_FIELDS:
            value = raw_event.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    f"Follow-on event {index} is missing required string field '{field}'."
                )

        event_id = str(raw_event["event_id"]).strip()
        if event_id in seen_ids:
            raise ValueError(f"Duplicate event_id found in sample input: {event_id}")
        seen_ids.add(event_id)

        normalized.append(
            {
                "event_id": event_id,
                "timestamp": parse_timestamp(str(raw_event["timestamp"])),
                "target_system": str(raw_event["target_system"]).strip(),
                "event_type": str(raw_event["event_type"]).strip(),
                "details": str(raw_event["details"]).strip(),
            }
        )

    return sorted(
        normalized,
        key=lambda event: (format_timestamp(event["timestamp"]), event["event_id"]),
    )


def evaluate_risky_config_changes(
    config_changes: Sequence[Mapping[str, Any]],
    rules: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    validated_rules = validate_rules(rules)
    hits: list[dict[str, Any]] = []
    for change in config_changes:
        if str(change["change_result"]) != "success":
            continue
        for rule in validated_rules:
            if str(change["config_key"]) != str(rule["config_key"]):
                continue
            if str(change["new_value"]).lower() not in rule["risky_values"]:
                continue
            hits.append(
                {
                    "investigation_id": "",
                    "rule_id": str(rule["rule_id"]),
                    "severity": str(rule["severity"]),
                    "reason": str(rule["reason"]),
                    "change_event": dict(change),
                }
            )
    hits.sort(
        key=lambda hit: (
            format_timestamp(hit["change_event"]["timestamp"]),
            str(hit["rule_id"]),
            str(hit["change_event"]["change_id"]),
        )
    )
    for index, hit in enumerate(hits, start=1):
        hit["investigation_id"] = f"CCI-{index:03d}"
    return hits


def validate_rules(rules: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    validated: list[dict[str, Any]] = []
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, Mapping):
            raise ValueError(f"Rule {index} must be a mapping.")
        for field in ("rule_id", "config_key", "severity", "reason"):
            value = rule.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Rule {index} is missing required string field '{field}'.")
        risky_values = rule.get("risky_values")
        if not isinstance(risky_values, list) or not risky_values:
            raise ValueError(f"Rule {index} must define a non-empty risky_values list.")
        if str(rule["severity"]).strip().lower() not in SEVERITY_ORDER:
            raise ValueError(f"Rule {index} uses unsupported severity '{rule['severity']}'.")
        validated.append(
            {
                "rule_id": str(rule["rule_id"]).strip(),
                "config_key": str(rule["config_key"]).strip(),
                "severity": str(rule["severity"]).strip().lower(),
                "reason": str(rule["reason"]).strip(),
                "risky_values": [str(value).strip().lower() for value in risky_values],
            }
        )
    return validated


def build_investigations(
    rule_hits: Sequence[Mapping[str, Any]],
    policy_denials: Sequence[Mapping[str, Any]],
    follow_on_events: Sequence[Mapping[str, Any]],
    correlation_minutes: int,
) -> list[dict[str, Any]]:
    investigations: list[dict[str, Any]] = []
    correlation_window = timedelta(minutes=correlation_minutes)

    for hit in rule_hits:
        change_event = hit["change_event"]
        change_time = change_event["timestamp"]
        window_end = change_time + correlation_window
        target_system = str(change_event["target_system"])

        attached_denials = [
            dict(denial)
            for denial in policy_denials
            if str(denial["target_system"]) == target_system
            and change_time <= denial["timestamp"] <= window_end
        ]
        attached_follow_on = [
            dict(event)
            for event in follow_on_events
            if str(event["target_system"]) == target_system
            and change_time <= event["timestamp"] <= window_end
        ]

        investigations.append(
            {
                "investigation_id": str(hit["investigation_id"]),
                "severity": str(hit["severity"]),
                "rule_id": str(hit["rule_id"]),
                "target_system": target_system,
                "actor": str(change_event["actor"]),
                "triggering_change": dict(change_event),
                "trigger_reason": str(hit["reason"]),
                "correlation_window_minutes": correlation_minutes,
                "bounded_correlation_reason": (
                    f"Attached evidence shares target_system '{target_system}' and falls within "
                    f"{correlation_minutes} minutes after the triggering change."
                ),
                "attached_policy_denials": attached_denials,
                "attached_follow_on_events": attached_follow_on,
                "evidence_counts": {
                    "policy_denials": len(attached_denials),
                    "follow_on_events": len(attached_follow_on),
                },
            }
        )

    return investigations


def build_investigation_summary(
    investigations: Sequence[Mapping[str, Any]],
    correlation_minutes: int,
) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for investigation in investigations:
        change = investigation["triggering_change"]
        counts = investigation["evidence_counts"]
        summary.append(
            {
                "investigation_id": str(investigation["investigation_id"]),
                "severity": str(investigation["severity"]),
                "target_system": str(investigation["target_system"]),
                "triggering_change_id": str(change["change_id"]),
                "summary": (
                    f"{change['config_key']} changed from {change['old_value']} to "
                    f"{change['new_value']} on {change['target_system']}, followed by "
                    f"{counts['policy_denials']} policy denials and "
                    f"{counts['follow_on_events']} follow-on events within "
                    f"{correlation_minutes} minutes."
                ),
                "evidence_counts": dict(counts),
                "bounded_correlation_reason": str(investigation["bounded_correlation_reason"]),
            }
        )
    return summary


def build_investigation_report(
    config_changes: Sequence[Mapping[str, Any]],
    rule_hits: Sequence[Mapping[str, Any]],
    investigations: Sequence[Mapping[str, Any]],
    correlation_minutes: int,
) -> str:
    lines = [
        "# Config-Change Investigation Demo Report",
        "",
        "This deterministic demo correlates risky configuration changes with bounded follow-on evidence.",
        "It does not use an LLM and does not produce autonomous response actions.",
        "",
        "## Run Summary",
        "",
        f"- normalized_change_events: {len(config_changes)}",
        f"- risky_change_hits: {len(rule_hits)}",
        f"- investigations: {len(investigations)}",
        f"- correlation_window_minutes: {correlation_minutes}",
        "",
    ]

    if not investigations:
        lines.append("No investigations were generated from the current sample.")
        return "\n".join(lines).rstrip() + "\n"

    for investigation in investigations:
        change = investigation["triggering_change"]
        counts = investigation["evidence_counts"]
        lines.extend(
            [
                f"## {investigation['investigation_id']}",
                "",
                f"- Severity: {investigation['severity']}",
                f"- Target system: {investigation['target_system']}",
                f"- Triggering change: {change['change_id']} ({change['config_key']} -> {change['new_value']})",
                f"- Trigger reason: {investigation['trigger_reason']}",
                f"- Attached policy denials: {counts['policy_denials']}",
                f"- Attached follow-on events: {counts['follow_on_events']}",
                f"- Bounded correlation: {investigation['bounded_correlation_reason']}",
                "",
            ]
        )

        if investigation["attached_policy_denials"]:
            lines.append("Policy denials:")
            for denial in investigation["attached_policy_denials"]:
                lines.append(
                    f"- {denial['denial_id']}: {denial['policy_name']} -> {denial['reason']}"
                )
            lines.append("")

        if investigation["attached_follow_on_events"]:
            lines.append("Follow-on events:")
            for event in investigation["attached_follow_on_events"]:
                lines.append(
                    f"- {event['event_id']}: {event['event_type']} -> {event['details']}"
                )
            lines.append("")

        if not investigation["attached_policy_denials"] and not investigation["attached_follow_on_events"]:
            lines.append(
                "No nearby supporting evidence fell inside the bounded correlation window."
            )
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_timestamp(raw_value: str) -> datetime:
    return datetime.fromisoformat(raw_value.replace("Z", "+00:00")).astimezone(UTC)


def format_timestamp(value: Any) -> str:
    timestamp = value if isinstance(value, datetime) else parse_timestamp(str(value))
    return timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")


def write_json(payload: Any, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(serialize_record(payload), indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def write_text(content: str, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
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
