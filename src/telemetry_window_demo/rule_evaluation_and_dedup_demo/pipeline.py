from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCOPE_FIELDS = ("entity", "source", "target", "host")
REQUIRED_HIT_FIELDS = (
    "hit_id",
    "rule_name",
    "severity",
    "alert_time",
    "window_start",
    "window_end",
    "message",
)


def default_demo_root() -> Path:
    return Path(__file__).resolve().parents[3] / "demos" / "rule-evaluation-and-dedup-demo"


def run_demo(
    demo_root: Path | None = None,
    artifacts_dir: Path | None = None,
) -> dict[str, Any]:
    demo_root = Path(demo_root or default_demo_root()).resolve()
    config = load_yaml(demo_root / "config" / "dedup.yaml")
    input_path = resolve_demo_path(
        demo_root,
        str(config.get("input_path", "data/raw/sample_rule_hits.json")),
    )
    cooldown_seconds = int(config.get("cooldown_seconds", 0))
    artifacts_dir = Path(
        artifacts_dir
        or resolve_demo_path(demo_root, str(config.get("artifacts_dir", "artifacts")))
    ).resolve()
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    raw_hits = load_json(input_path)
    normalized_hits = normalize_rule_hits(raw_hits)
    retained_hits, explanations = deduplicate_rule_hits(
        normalized_hits,
        cooldown_seconds=cooldown_seconds,
    )
    group_summaries = build_group_summaries(
        normalized_hits,
        retained_hits,
        explanations,
    )
    report_text = build_dedup_report(
        normalized_hits,
        retained_hits,
        explanations,
        group_summaries,
        cooldown_seconds=cooldown_seconds,
    )

    paths = {
        "rule_hits_before_dedup": write_json(
            normalized_hits,
            artifacts_dir / "rule_hits_before_dedup.json",
        ),
        "rule_hits_after_dedup": write_json(
            retained_hits,
            artifacts_dir / "rule_hits_after_dedup.json",
        ),
        "dedup_explanations": write_json(
            explanations,
            artifacts_dir / "dedup_explanations.json",
        ),
        "dedup_report": write_text(report_text, artifacts_dir / "dedup_report.md"),
    }

    return {
        "demo_root": demo_root,
        "artifacts_dir": artifacts_dir,
        "cooldown_seconds": cooldown_seconds,
        "raw_hit_count": len(normalized_hits),
        "retained_alert_count": len(retained_hits),
        "suppressed_hit_count": sum(
            1 for explanation in explanations if explanation["status"] == "suppressed"
        ),
        "group_count": len(group_summaries),
        "artifacts": paths,
    }


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise ValueError("YAML config must deserialize into a mapping.")
    return payload


def resolve_demo_path(demo_root: Path, value: str) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate
    return (demo_root / candidate).resolve()


def normalize_rule_hits(raw_hits: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_hits, list):
        raise ValueError("Raw rule hits input must be a list of mappings.")

    normalized_hits: list[dict[str, Any]] = []
    seen_hit_ids: set[str] = set()

    for index, raw_hit in enumerate(raw_hits, start=1):
        if not isinstance(raw_hit, Mapping):
            raise ValueError(f"Rule hit {index} must be a mapping.")

        for field in REQUIRED_HIT_FIELDS:
            value = raw_hit.get(field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Rule hit {index} is missing required string field '{field}'.")

        hit_id = str(raw_hit["hit_id"]).strip()
        if hit_id in seen_hit_ids:
            raise ValueError(f"Duplicate hit_id found in sample input: {hit_id}")
        seen_hit_ids.add(hit_id)

        alert_time = parse_timestamp(str(raw_hit["alert_time"]))
        window_start = parse_timestamp(str(raw_hit["window_start"]))
        window_end = parse_timestamp(str(raw_hit["window_end"]))
        if window_start > window_end:
            raise ValueError(f"Rule hit {hit_id} has window_start after window_end.")
        if alert_time != window_end:
            raise ValueError(f"Rule hit {hit_id} must use window_end as alert_time.")

        cooldown_scope, scope_source = resolve_cooldown_scope(raw_hit)
        normalized_hit = {
            "hit_id": hit_id,
            "rule_name": str(raw_hit["rule_name"]).strip(),
            "severity": str(raw_hit["severity"]).strip(),
            "alert_time": alert_time,
            "window_start": window_start,
            "window_end": window_end,
            "message": str(raw_hit["message"]).strip(),
            "entity": normalize_optional_text(raw_hit.get("entity")),
            "source": normalize_optional_text(raw_hit.get("source")),
            "target": normalize_optional_text(raw_hit.get("target")),
            "host": normalize_optional_text(raw_hit.get("host")),
            "cooldown_scope": cooldown_scope,
            "scope_source": scope_source,
            "cooldown_key": build_cooldown_key(
                str(raw_hit["rule_name"]).strip(),
                cooldown_scope,
            ),
        }
        normalized_hits.append(normalized_hit)

    return sorted(normalized_hits, key=rule_hit_sort_key)


def normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def resolve_cooldown_scope(rule_hit: Mapping[str, Any]) -> tuple[str | None, str]:
    for field in SCOPE_FIELDS:
        value = normalize_optional_text(rule_hit.get(field))
        if value:
            return f"{field}={value}", field
    return None, "unscoped"


def group_rule_hits_by_cooldown_key(
    rule_hits: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for rule_hit in rule_hits:
        grouped[str(rule_hit["cooldown_key"])].append(rule_hit)

    group_summaries: list[dict[str, Any]] = []
    for cooldown_key, group_hits in grouped.items():
        ordered_hits = sorted(group_hits, key=rule_hit_sort_key)
        first_hit = ordered_hits[0]
        last_hit = ordered_hits[-1]
        group_summaries.append(
            {
                "cooldown_key": cooldown_key,
                "rule_name": str(first_hit["rule_name"]),
                "cooldown_scope": first_hit.get("cooldown_scope"),
                "scope_source": str(first_hit["scope_source"]),
                "first_seen": first_hit["alert_time"],
                "last_seen": last_hit["alert_time"],
                "raw_hit_count": len(ordered_hits),
                "hit_ids": [str(hit["hit_id"]) for hit in ordered_hits],
            }
        )

    return sorted(
        group_summaries,
        key=lambda group: (group["first_seen"], str(group["cooldown_key"])),
    )


def deduplicate_rule_hits(
    rule_hits: Sequence[Mapping[str, Any]],
    *,
    cooldown_seconds: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ordered_hits = [dict(rule_hit) for rule_hit in sorted(rule_hits, key=rule_hit_sort_key)]
    group_summaries = group_rule_hits_by_cooldown_key(ordered_hits)
    group_sizes = {
        str(group["cooldown_key"]): int(group["raw_hit_count"]) for group in group_summaries
    }
    seen_positions: dict[str, int] = defaultdict(int)
    last_retained_by_key: dict[str, dict[str, Any]] = {}
    active_anchor_hit_id_by_key: dict[str, str] = {}
    retained_hits: list[dict[str, Any]] = []
    retained_hits_by_id: dict[str, dict[str, Any]] = {}
    explanations: list[dict[str, Any]] = []

    for rule_hit in ordered_hits:
        cooldown_key = str(rule_hit["cooldown_key"])
        seen_positions[cooldown_key] += 1
        group_position = seen_positions[cooldown_key]
        group_size = group_sizes[cooldown_key]
        last_retained = last_retained_by_key.get(cooldown_key)

        if cooldown_seconds <= 0 or last_retained is None:
            reason = build_retained_reason(
                rule_hit,
                previous_retained=None,
                cooldown_seconds=cooldown_seconds,
            )
            retained_record = build_retained_record(
                rule_hit,
                reason=reason,
                group_position=group_position,
                group_size=group_size,
            )
            retained_hits.append(retained_record)
            retained_hits_by_id[retained_record["hit_id"]] = retained_record
            last_retained_by_key[cooldown_key] = dict(rule_hit)
            active_anchor_hit_id_by_key[cooldown_key] = retained_record["hit_id"]
            explanations.append(
                build_explanation_record(
                    rule_hit,
                    status="retained",
                    reason=reason,
                    group_position=group_position,
                    group_size=group_size,
                    cooldown_seconds=cooldown_seconds,
                    suppressed_by_hit_id=None,
                    seconds_since_last_retained=None,
                )
            )
            continue

        elapsed_seconds = int(
            (
                parse_timestamp(str(rule_hit["alert_time"]))
                - parse_timestamp(str(last_retained["alert_time"]))
            ).total_seconds()
        )
        if elapsed_seconds >= cooldown_seconds:
            reason = build_retained_reason(
                rule_hit,
                previous_retained=last_retained,
                cooldown_seconds=cooldown_seconds,
            )
            retained_record = build_retained_record(
                rule_hit,
                reason=reason,
                group_position=group_position,
                group_size=group_size,
            )
            retained_hits.append(retained_record)
            retained_hits_by_id[retained_record["hit_id"]] = retained_record
            last_retained_by_key[cooldown_key] = dict(rule_hit)
            active_anchor_hit_id_by_key[cooldown_key] = retained_record["hit_id"]
            explanations.append(
                build_explanation_record(
                    rule_hit,
                    status="retained",
                    reason=reason,
                    group_position=group_position,
                    group_size=group_size,
                    cooldown_seconds=cooldown_seconds,
                    suppressed_by_hit_id=None,
                    seconds_since_last_retained=elapsed_seconds,
                )
            )
            continue

        anchor_hit_id = active_anchor_hit_id_by_key[cooldown_key]
        reason = build_suppression_reason(
            rule_hit,
            previous_retained=last_retained,
            cooldown_seconds=cooldown_seconds,
            elapsed_seconds=elapsed_seconds,
        )
        retained_hits_by_id[anchor_hit_id]["suppressed_hit_ids"].append(rule_hit["hit_id"])
        retained_hits_by_id[anchor_hit_id]["suppression_reasons"].append(reason)
        explanations.append(
            build_explanation_record(
                rule_hit,
                status="suppressed",
                reason=reason,
                group_position=group_position,
                group_size=group_size,
                cooldown_seconds=cooldown_seconds,
                suppressed_by_hit_id=anchor_hit_id,
                seconds_since_last_retained=elapsed_seconds,
            )
        )

    retained_counts_by_key: dict[str, int] = defaultdict(int)
    for retained_hit in retained_hits:
        retained_counts_by_key[str(retained_hit["cooldown_key"])] += 1

    for retained_hit in retained_hits:
        represented_hit_ids = [retained_hit["hit_id"], *retained_hit["suppressed_hit_ids"]]
        retained_hit["represented_hit_ids"] = represented_hit_ids
        retained_hit["represented_raw_hit_count"] = len(represented_hit_ids)
        retained_hit["suppressed_count"] = len(retained_hit["suppressed_hit_ids"])
        retained_hit["group_raw_hit_count"] = group_sizes[str(retained_hit["cooldown_key"])]
        retained_hit["group_retained_alert_count"] = retained_counts_by_key[
            str(retained_hit["cooldown_key"])
        ]

    return retained_hits, explanations


def build_retained_record(
    rule_hit: Mapping[str, Any],
    *,
    reason: str,
    group_position: int,
    group_size: int,
) -> dict[str, Any]:
    record = dict(rule_hit)
    record["retained_because"] = reason
    record["group_position"] = group_position
    record["group_size"] = group_size
    record["suppressed_hit_ids"] = []
    record["suppression_reasons"] = []
    record["suppressed_count"] = 0
    return record


def build_explanation_record(
    rule_hit: Mapping[str, Any],
    *,
    status: str,
    reason: str,
    group_position: int,
    group_size: int,
    cooldown_seconds: int,
    suppressed_by_hit_id: str | None,
    seconds_since_last_retained: int | None,
) -> dict[str, Any]:
    return {
        "hit_id": str(rule_hit["hit_id"]),
        "rule_name": str(rule_hit["rule_name"]),
        "severity": str(rule_hit["severity"]),
        "alert_time": rule_hit["alert_time"],
        "cooldown_scope": rule_hit.get("cooldown_scope"),
        "scope_source": str(rule_hit["scope_source"]),
        "cooldown_key": str(rule_hit["cooldown_key"]),
        "status": status,
        "reason": reason,
        "group_position": group_position,
        "group_size": group_size,
        "cooldown_seconds": cooldown_seconds,
        "suppressed_by_hit_id": suppressed_by_hit_id,
        "seconds_since_last_retained": seconds_since_last_retained,
        "message": str(rule_hit["message"]),
    }


def build_group_summaries(
    rule_hits: Sequence[Mapping[str, Any]],
    retained_hits: Sequence[Mapping[str, Any]],
    explanations: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    grouped = group_rule_hits_by_cooldown_key(rule_hits)
    retained_hit_ids_by_key: dict[str, list[str]] = defaultdict(list)
    suppressed_hit_ids_by_key: dict[str, list[str]] = defaultdict(list)

    for retained_hit in retained_hits:
        retained_hit_ids_by_key[str(retained_hit["cooldown_key"])].append(
            str(retained_hit["hit_id"])
        )

    for explanation in explanations:
        if explanation["status"] != "suppressed":
            continue
        suppressed_hit_ids_by_key[str(explanation["cooldown_key"])].append(
            str(explanation["hit_id"])
        )

    output: list[dict[str, Any]] = []
    for group in grouped:
        cooldown_key = str(group["cooldown_key"])
        output.append(
            {
                "cooldown_key": cooldown_key,
                "rule_name": str(group["rule_name"]),
                "cooldown_scope": group.get("cooldown_scope"),
                "scope_source": str(group["scope_source"]),
                "first_seen": group["first_seen"],
                "last_seen": group["last_seen"],
                "raw_hit_count": int(group["raw_hit_count"]),
                "retained_alert_count": len(retained_hit_ids_by_key[cooldown_key]),
                "suppressed_hit_count": len(suppressed_hit_ids_by_key[cooldown_key]),
                "hit_ids": list(group["hit_ids"]),
                "retained_hit_ids": retained_hit_ids_by_key[cooldown_key],
                "suppressed_hit_ids": suppressed_hit_ids_by_key[cooldown_key],
            }
        )
    return output


def build_dedup_report(
    rule_hits: Sequence[Mapping[str, Any]],
    retained_hits: Sequence[Mapping[str, Any]],
    explanations: Sequence[Mapping[str, Any]],
    group_summaries: Sequence[Mapping[str, Any]],
    *,
    cooldown_seconds: int,
) -> str:
    suppressed_explanations = [
        explanation
        for explanation in explanations
        if explanation["status"] == "suppressed"
    ]
    lines = [
        "# Rule Evaluation And Dedup Demo Report",
        "",
        "This deterministic demo shows how repeated raw rule hits turn into fewer retained alerts after cooldown handling.",
        "Cooldown keys are built from `(rule_name, scope)`, where scope prefers `entity`, then `source`, then `target`, then `host`, and falls back to rule-only dedup when none are present.",
        "",
        "## Run Summary",
        "",
        f"- raw_rule_hits: {len(rule_hits)}",
        f"- retained_alerts: {len(retained_hits)}",
        f"- suppressed_hits: {len(suppressed_explanations)}",
        f"- cooldown_seconds: {cooldown_seconds}",
        "",
        "## Group Summary",
        "",
        "| Rule / scope | Raw hits | Retained | Suppressed | First seen | Last seen |",
        "| --- | ---: | ---: | ---: | --- | --- |",
    ]

    for group in group_summaries:
        lines.append(
            "| "
            f"{format_rule_scope(str(group['rule_name']), group.get('cooldown_scope'))} | "
            f"{group['raw_hit_count']} | "
            f"{group['retained_alert_count']} | "
            f"{group['suppressed_hit_count']} | "
            f"{format_timestamp(group['first_seen'])} | "
            f"{format_timestamp(group['last_seen'])} |"
        )

    lines.extend(
        [
            "",
            "## Retained Alerts",
            "",
        ]
    )

    for retained_hit in retained_hits:
        lines.append(
            "- "
            f"{retained_hit['hit_id']} kept for "
            f"`{format_rule_scope(str(retained_hit['rule_name']), retained_hit.get('cooldown_scope'))}`; "
            f"{retained_hit['retained_because']}"
        )
        if retained_hit["suppressed_hit_ids"]:
            lines.append(
                "  "
                f"Represents suppressed duplicates: {', '.join(retained_hit['suppressed_hit_ids'])}."
            )

    lines.extend(
        [
            "",
            "## Suppressed Hits",
            "",
        ]
    )

    if not suppressed_explanations:
        lines.append("- none")
    else:
        for explanation in suppressed_explanations:
            lines.append(
                "- "
                f"{explanation['hit_id']} suppressed by {explanation['suppressed_by_hit_id']} for "
                f"`{format_rule_scope(str(explanation['rule_name']), explanation.get('cooldown_scope'))}`; "
                f"{explanation['reason']}"
            )

    return "\n".join(lines).rstrip() + "\n"


def build_retained_reason(
    rule_hit: Mapping[str, Any],
    *,
    previous_retained: Mapping[str, Any] | None,
    cooldown_seconds: int,
) -> str:
    scope_label = format_rule_scope(str(rule_hit["rule_name"]), rule_hit.get("cooldown_scope"))
    if cooldown_seconds <= 0:
        return f"kept because cooldown is disabled for `{scope_label}`."
    if previous_retained is None:
        return f"kept as the first hit for `{scope_label}`."

    elapsed_seconds = int(
        (
            parse_timestamp(str(rule_hit["alert_time"]))
            - parse_timestamp(str(previous_retained["alert_time"]))
        ).total_seconds()
    )
    return (
        f"kept because {elapsed_seconds} seconds elapsed since retained hit "
        f"`{previous_retained['hit_id']}`, which meets the {cooldown_seconds} second cooldown."
    )


def build_suppression_reason(
    rule_hit: Mapping[str, Any],
    *,
    previous_retained: Mapping[str, Any],
    cooldown_seconds: int,
    elapsed_seconds: int,
) -> str:
    return (
        f"suppressed because it matched the same cooldown key as retained hit "
        f"`{previous_retained['hit_id']}` only {elapsed_seconds} seconds later, inside the "
        f"{cooldown_seconds} second cooldown."
    )


def build_cooldown_key(rule_name: str, cooldown_scope: str | None) -> str:
    return f"{rule_name}|{cooldown_scope or 'unscoped'}"


def format_rule_scope(rule_name: str, cooldown_scope: Any) -> str:
    scope = str(cooldown_scope).strip() if cooldown_scope is not None else ""
    return f"{rule_name} / {scope or 'unscoped'}"


def rule_hit_sort_key(rule_hit: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        format_timestamp(rule_hit["alert_time"]),
        str(rule_hit["rule_name"]),
        str(rule_hit.get("cooldown_scope") or ""),
        str(rule_hit["hit_id"]),
    )


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


def parse_timestamp(raw_value: str) -> datetime:
    return datetime.fromisoformat(raw_value.replace("Z", "+00:00")).astimezone(UTC)


def format_timestamp(value: Any) -> str:
    timestamp = value if isinstance(value, datetime) else parse_timestamp(str(value))
    return timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")


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
