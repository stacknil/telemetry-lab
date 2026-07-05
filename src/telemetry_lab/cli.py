from __future__ import annotations

import argparse
import math
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .features import compute_window_features
from .io import (
    format_timestamp,
    load_alert_table,
    load_config,
    load_events,
    load_feature_table,
    resolve_config_path,
    write_json,
    write_table,
)
from .manifest import RUN_MANIFEST_SCHEMA_VERSION, build_run_manifest, write_run_manifest
from .preprocess import normalize_events
from .rules import apply_rules
from .schema import DEFAULT_TIMESTAMP_COLUMN, REQUIRED_EVENT_COLUMNS
from .visualize import plot_outputs
from .windowing import build_windows

RUN_RULE_SECTION_NAMES = (
    "high_error_rate",
    "login_fail_burst",
    "high_severity_spike",
    "persistent_high_error",
    "source_spread_spike",
    "rare_event_repeat",
)
RUN_RULE_CONFIG_FIELDS = {
    "high_error_rate": frozenset(("threshold", "severity")),
    "login_fail_burst": frozenset(("threshold", "severity")),
    "high_severity_spike": frozenset(("threshold", "severity")),
    "persistent_high_error": frozenset(
        ("threshold", "consecutive_windows", "severity")
    ),
    "source_spread_spike": frozenset(("absolute_threshold", "multiplier", "severity")),
    "rare_event_repeat": frozenset(("threshold", "event_types", "severity")),
}
RUN_CONFIG_FIELDS = frozenset(("input_path", "output_dir", "time", "features", "rules"))
RUN_TIME_CONFIG_FIELDS = frozenset(
    ("timestamp_col", "window_size_seconds", "step_size_seconds")
)
RUN_FEATURE_CONFIG_FIELDS = frozenset(
    ("count_event_types", "error_statuses", "severity_levels")
)


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (OSError, ValueError) as exc:
        parser.exit(status=1, message=f"error: {exc}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="telemetry-lab",
        description="Local, file-based telemetry workflow lab.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run a telemetry-lab demo.")
    run_parser.add_argument(
        "--config",
        help="Compatibility path for the window demo YAML config.",
    )
    run_subparsers = run_parser.add_subparsers(dest="demo_id")
    run_parser.set_defaults(func=run_command)

    window_parser = run_subparsers.add_parser(
        "window",
        help="Run the window feature and alert demo.",
    )
    window_parser.add_argument("--config", required=True, help="Path to a YAML config file.")
    window_parser.set_defaults(func=run_window_demo_command)

    ai_parser = run_subparsers.add_parser(
        "ai-assisted",
        help="Run the constrained AI-assisted detection demo.",
    )
    ai_parser.add_argument("--demo-root", help="Path to demos/ai-assisted-detection-demo.")
    ai_parser.set_defaults(func=run_ai_demo_command)

    dedup_parser = run_subparsers.add_parser(
        "dedup",
        help="Run the rule evaluation and dedup demo.",
    )
    dedup_parser.add_argument("--demo-root", help="Path to demos/rule-evaluation-and-dedup-demo.")
    dedup_parser.set_defaults(func=run_rule_dedup_demo_command)

    config_change_parser = run_subparsers.add_parser(
        "config-change",
        help="Run the config-change investigation demo.",
    )
    config_change_parser.add_argument(
        "--demo-root",
        help="Path to demos/config-change-investigation-demo.",
    )
    config_change_parser.set_defaults(func=run_config_change_demo_command)

    cloud_iam_parser = run_subparsers.add_parser(
        "cloud-iam",
        help="Run the synthetic CloudTrail-like IAM change investigation demo.",
    )
    cloud_iam_parser.add_argument(
        "--demo-root",
        help="Path to demos/cloud-iam-change-investigation-demo.",
    )
    cloud_iam_parser.set_defaults(func=run_cloud_iam_demo_command)

    summarize_parser = subparsers.add_parser(
        "summarize",
        help="Summarize an input event file.",
    )
    summarize_parser.add_argument("--input", required=True, help="Path to .jsonl or .csv.")
    summarize_parser.add_argument(
        "--timestamp-col",
        default=DEFAULT_TIMESTAMP_COLUMN,
        help="Timestamp column name in the input event file.",
    )
    summarize_parser.set_defaults(func=summarize_command)

    plot_parser = subparsers.add_parser("plot", help="Render plots from CSV outputs.")
    plot_parser.add_argument("--features", required=True, help="Path to features.csv.")
    plot_parser.add_argument("--alerts", help="Path to alerts.csv.")
    plot_parser.add_argument(
        "--output-dir",
        default="data/processed",
        help="Directory where plot images will be written.",
    )
    plot_parser.set_defaults(func=plot_command)

    run_ai_demo_parser = subparsers.add_parser(
        "run-ai-demo",
        help="Run the constrained AI-assisted detection demo with JSON-only summarization.",
    )
    run_ai_demo_parser.add_argument(
        "--demo-root",
        help="Path to demos/ai-assisted-detection-demo.",
    )
    run_ai_demo_parser.set_defaults(func=run_ai_demo_command)

    run_rule_dedup_demo_parser = subparsers.add_parser(
        "run-rule-dedup-demo",
        help="Run the rule evaluation and dedup demo with suppression explanations.",
    )
    run_rule_dedup_demo_parser.add_argument(
        "--demo-root",
        help="Path to demos/rule-evaluation-and-dedup-demo.",
    )
    run_rule_dedup_demo_parser.set_defaults(func=run_rule_dedup_demo_command)

    run_config_change_demo_parser = subparsers.add_parser(
        "run-config-change-demo",
        help="Run the config-change investigation demo with deterministic correlation.",
    )
    run_config_change_demo_parser.add_argument(
        "--demo-root",
        help="Path to demos/config-change-investigation-demo.",
    )
    run_config_change_demo_parser.set_defaults(func=run_config_change_demo_command)

    run_cloud_iam_demo_parser = subparsers.add_parser(
        "run-cloud-iam-change-demo",
        help="Run the synthetic CloudTrail-like IAM change investigation demo.",
    )
    run_cloud_iam_demo_parser.add_argument(
        "--demo-root",
        help="Path to demos/cloud-iam-change-investigation-demo.",
    )
    run_cloud_iam_demo_parser.set_defaults(func=run_cloud_iam_demo_command)

    verify_parser = subparsers.add_parser(
        "verify",
        help="Run the reviewer-friendly release contract gate.",
    )
    verify_parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable used for the gate. Defaults to this interpreter.",
    )
    verify_parser.set_defaults(func=verify_command)

    return parser


def run_command(args: argparse.Namespace) -> None:
    if not getattr(args, "config", None):
        raise ValueError(
            "Run command requires a demo name. Use `telemetry-lab run window --config "
            "configs/default.yaml` or the compatibility form `run --config ...`."
        )
    run_window_demo_command(args)


def run_window_demo_command(args: argparse.Namespace) -> None:
    config_path = Path(args.config).resolve()
    config = load_config(config_path)
    run_config = _validate_run_config(config)
    time_config = run_config["time"]
    feature_config = run_config["features"]
    rules_config = run_config["rules"]
    input_path = resolve_config_path(config_path, run_config["input_path"])
    output_dir = resolve_config_path(config_path, run_config["output_dir"])
    timestamp_col = time_config["timestamp_col"]

    events = load_events(input_path, timestamp_col=timestamp_col)
    normalized = normalize_events(
        events,
        timestamp_col=timestamp_col,
        error_statuses=feature_config.get("error_statuses"),
        high_severity_levels=feature_config.get("severity_levels"),
    )
    windows = build_windows(
        normalized,
        timestamp_col=timestamp_col,
        window_size_seconds=time_config["window_size_seconds"],
        step_size_seconds=time_config["step_size_seconds"],
    )
    features = compute_window_features(
        normalized,
        windows,
        count_event_types=feature_config.get("count_event_types"),
    )
    alerts = apply_rules(features, rules_config)
    cooldown_seconds = rules_config["cooldown_seconds"]

    feature_path = write_table(features, output_dir / "features.csv")
    alert_path = write_table(alerts, output_dir / "alerts.csv")
    plot_paths = plot_outputs(features, alerts, output_dir)
    summary_path = output_dir / "summary.json"
    manifest_path = output_dir / "run_manifest.json"
    manifest = build_run_manifest(
        demo_id="window",
        input_files={Path(input_path).name: input_path},
        config_files={Path(config_path).name: config_path},
        artifact_schema_versions={
            "run_manifest": RUN_MANIFEST_SCHEMA_VERSION,
            "telemetry_summary": "telemetry-summary/v1",
        },
    )
    summary = _build_run_summary(
        input_path=input_path,
        output_dir=output_dir,
        normalized=normalized,
        windows=windows,
        features=features,
        alerts=alerts,
        cooldown_seconds=cooldown_seconds,
        feature_path=feature_path,
        alert_path=alert_path,
        summary_path=summary_path,
        manifest_path=manifest_path,
        plot_paths=plot_paths,
    )
    write_json(summary, summary_path)
    write_run_manifest(manifest, manifest_path)

    print(f"[OK] Loaded {len(normalized)} events")
    print(f"[OK] Generated {len(features)} windows")
    print(f"[OK] Computed {max(len(features.columns) - 2, 0)} features per window")
    print(f"[OK] Triggered {len(alerts)} alerts")
    print(f"[OK] Saved {feature_path.name}, {alert_path.name}")
    print(f"[OK] Saved plots to {_display_path(output_dir)}")
    for plot_path in plot_paths:
        print(f"     - {plot_path.name}")
    print(f"[OK] Saved run manifest to {_display_path(manifest_path)}")


def summarize_command(args: argparse.Namespace) -> None:
    timestamp_col = _timestamp_column_config_value(
        args.timestamp_col,
        "timestamp-col",
    )
    events = normalize_events(
        load_events(args.input, timestamp_col=timestamp_col),
        timestamp_col=timestamp_col,
    )
    min_time = format_timestamp(events[timestamp_col].min())
    max_time = format_timestamp(events[timestamp_col].max())
    top_event_types = events["event_type"].value_counts().head(5).to_dict()
    overall_error_rate = float(events["is_error"].mean()) if not events.empty else 0.0

    print(f"events: {len(events)}")
    print(f"time_range: {min_time} -> {max_time}")
    print(f"unique_sources: {events['source'].nunique()}")
    print(f"unique_targets: {events['target'].nunique()}")
    print(f"overall_error_rate: {overall_error_rate:.2f}")
    print(f"top_event_types: {top_event_types}")


def plot_command(args: argparse.Namespace) -> None:
    features = load_feature_table(args.features)
    alerts = (
        load_alert_table(args.alerts)
        if args.alerts
        else load_alert_table(Path(args.features).with_name("alerts.csv"))
    )
    plot_paths = plot_outputs(features, alerts, args.output_dir)
    print(f"[OK] Saved plots to {_display_path(Path(args.output_dir).resolve())}")
    for plot_path in plot_paths:
        print(f"     - {plot_path.name}")


def run_ai_demo_command(args: argparse.Namespace) -> None:
    from .ai_assisted_detection_demo import default_demo_root, run_demo

    demo_root = _demo_root_path(args.demo_root, default_demo_root())
    result = run_demo(demo_root=demo_root)

    print(f"[OK] Loaded {result['raw_event_count']} raw events")
    print(f"[OK] Normalized {result['normalized_event_count']} events")
    print(f"[OK] Triggered {result['rule_hit_count']} rule hits")
    print(f"[OK] Built {result['case_count']} cases")
    print(f"[OK] Validated {result['summary_count']} JSON summaries")
    print(f"[OK] Rejected {result['rejected_summary_count']} summaries")
    print(f"[OK] Wrote {result['audit_record_count']} audit records")
    print(f"[OK] Saved artifacts to {_display_path(result['artifacts_dir'])}")
    for name, path in result["artifacts"].items():
        print(f"     - {name}: {_display_path(path)}")


def run_rule_dedup_demo_command(args: argparse.Namespace) -> None:
    from .rule_evaluation_and_dedup_demo import default_demo_root, run_demo

    demo_root = _demo_root_path(args.demo_root, default_demo_root())
    result = run_demo(demo_root=demo_root)

    print(f"[OK] Loaded {result['raw_hit_count']} raw rule hits")
    print(f"[OK] Retained {result['retained_alert_count']} alerts")
    print(f"[OK] Suppressed {result['suppressed_hit_count']} repeated hits")
    print(f"[OK] Evaluated {result['group_count']} rule/scope groups")
    print(f"[OK] Saved artifacts to {_display_path(result['artifacts_dir'])}")
    for name, path in result["artifacts"].items():
        print(f"     - {name}: {_display_path(path)}")


def run_config_change_demo_command(args: argparse.Namespace) -> None:
    from .config_change_investigation_demo import default_demo_root, run_demo

    demo_root = _demo_root_path(args.demo_root, default_demo_root())
    result = run_demo(demo_root=demo_root)

    print(f"[OK] Loaded {result['change_event_count']} config changes")
    print(f"[OK] Flagged {result['risky_change_count']} risky changes")
    print(f"[OK] Built {result['investigation_count']} investigations")
    print(f"[OK] Saved artifacts to {_display_path(result['artifacts_dir'])}")
    for name, path in result["artifacts"].items():
        print(f"     - {name}: {_display_path(path)}")


def run_cloud_iam_demo_command(args: argparse.Namespace) -> None:
    from .cloud_iam_change_investigation_demo import default_demo_root, run_demo

    demo_root = _demo_root_path(args.demo_root, default_demo_root())
    result = run_demo(demo_root=demo_root)

    print(f"[OK] Loaded {result['raw_event_count']} CloudTrail-like events")
    print(f"[OK] Evaluated {result['rule_count']} investigation rules")
    print(f"[OK] Built {result['signal_count']} investigation signals")
    print(f"[OK] Saved artifacts to {_display_path(result['artifacts_dir'])}")
    for name, path in result["artifacts"].items():
        print(f"     - {name}: {_display_path(path)}")


def verify_command(args: argparse.Namespace) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "check_release_contract.py"
    if not script_path.is_file():
        raise FileNotFoundError(
            "Release contract script not found. Run this command from a telemetry-lab "
            "source checkout."
        )
    completed = subprocess.run(
        [args.python, str(script_path.relative_to(repo_root))],
        cwd=repo_root,
        check=False,
    )
    raise SystemExit(completed.returncode)


def _display_path(path: Path) -> str:
    cwd = Path.cwd().resolve()
    resolved = path.resolve()
    try:
        return resolved.relative_to(cwd).as_posix()
    except ValueError:
        return resolved.as_posix()


def _demo_root_path(value: str | None, default_root: Path) -> Path:
    demo_root = Path(value).resolve() if value else default_root.resolve()
    if not demo_root.exists():
        raise FileNotFoundError(f"Demo root not found: {demo_root}")
    if not demo_root.is_dir():
        raise ValueError(f"Demo root path is not a directory: {demo_root}")
    return demo_root


def _validate_run_config(config: Mapping[str, Any]) -> dict[str, Any]:
    _reject_unknown_config_fields(config, RUN_CONFIG_FIELDS)

    time_config = _optional_mapping(config.get("time", {}), "time")
    _reject_unknown_config_fields(time_config, RUN_TIME_CONFIG_FIELDS, parent="time")

    feature_config = _optional_mapping(config.get("features", {}), "features")
    _reject_unknown_config_fields(
        feature_config,
        RUN_FEATURE_CONFIG_FIELDS,
        parent="features",
    )

    rules_config = _validate_rules_config(config.get("rules"))

    return {
        "input_path": _path_config_value(config.get("input_path"), "input_path"),
        "output_dir": _path_config_value(
            config.get("output_dir", "data/processed"),
            "output_dir",
        ),
        "time": {
            "timestamp_col": _timestamp_column_config_value(
                time_config.get("timestamp_col", "timestamp"),
                "time.timestamp_col",
            ),
            "window_size_seconds": _int_config_value(
                time_config.get("window_size_seconds", 60),
                "time.window_size_seconds",
                minimum=1,
            ),
            "step_size_seconds": _int_config_value(
                time_config.get("step_size_seconds", 10),
                "time.step_size_seconds",
                minimum=1,
            ),
        },
        "features": {
            "count_event_types": _optional_string_sequence(
                feature_config.get("count_event_types"),
                "features.count_event_types",
            ),
            "error_statuses": _optional_string_sequence(
                feature_config.get("error_statuses"),
                "features.error_statuses",
            ),
            "severity_levels": _optional_string_sequence(
                feature_config.get("severity_levels"),
                "features.severity_levels",
            ),
        },
        "rules": rules_config,
    }


def _validate_rules_config(raw_rules_config: Any) -> dict[str, Any]:
    rules_config = (
        {}
        if raw_rules_config is None
        else dict(_optional_mapping(raw_rules_config, "rules"))
    )
    allowed_rule_keys = {"cooldown_seconds", *RUN_RULE_SECTION_NAMES}
    _reject_unknown_config_fields(rules_config, allowed_rule_keys, parent="rules")

    rules_config["cooldown_seconds"] = _int_config_value(
        rules_config.get("cooldown_seconds", 0),
        "rules.cooldown_seconds",
        minimum=0,
    )

    for rule_name in RUN_RULE_SECTION_NAMES:
        if rule_name in rules_config:
            rule_config = dict(
                _optional_mapping(
                    rules_config[rule_name],
                    f"rules.{rule_name}",
                )
            )
            rules_config[rule_name] = _validate_rule_section_config(
                rule_name,
                rule_config,
            )

    return rules_config


def _validate_rule_section_config(
    rule_name: str,
    rule_config: dict[str, Any],
) -> dict[str, Any]:
    allowed_fields = RUN_RULE_CONFIG_FIELDS[rule_name]
    _reject_unknown_config_fields(
        rule_config,
        allowed_fields,
        parent=f"rules.{rule_name}",
    )

    if "severity" in rule_config:
        rule_config["severity"] = _string_config_value(
            rule_config["severity"],
            f"rules.{rule_name}.severity",
        )

    if rule_name == "high_error_rate":
        _normalize_optional_float(
            rule_config,
            "threshold",
            "rules.high_error_rate.threshold",
            minimum=0.0,
        )
    elif rule_name == "login_fail_burst":
        _normalize_optional_int(
            rule_config,
            "threshold",
            "rules.login_fail_burst.threshold",
            minimum=1,
        )
    elif rule_name == "high_severity_spike":
        _normalize_optional_int(
            rule_config,
            "threshold",
            "rules.high_severity_spike.threshold",
            minimum=1,
        )
    elif rule_name == "persistent_high_error":
        _normalize_optional_float(
            rule_config,
            "threshold",
            "rules.persistent_high_error.threshold",
            minimum=0.0,
        )
        _normalize_optional_int(
            rule_config,
            "consecutive_windows",
            "rules.persistent_high_error.consecutive_windows",
            minimum=1,
        )
    elif rule_name == "source_spread_spike":
        _normalize_optional_int(
            rule_config,
            "absolute_threshold",
            "rules.source_spread_spike.absolute_threshold",
            minimum=1,
        )
        _normalize_optional_float(
            rule_config,
            "multiplier",
            "rules.source_spread_spike.multiplier",
            minimum=1.0,
        )
    elif rule_name == "rare_event_repeat":
        _normalize_optional_int(
            rule_config,
            "threshold",
            "rules.rare_event_repeat.threshold",
            minimum=1,
        )
        if "event_types" in rule_config:
            rule_config["event_types"] = _string_sequence(
                rule_config["event_types"],
                "rules.rare_event_repeat.event_types",
            )

    return rule_config


def _optional_mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"Config field '{field_name}' must be a mapping.")
    return value


def _reject_unknown_config_fields(
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


def _path_config_value(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Config field '{field_name}' must be a non-empty path string.")
    return value.strip()


def _string_config_value(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Config field '{field_name}' must be a non-empty string.")
    return value.strip()


def _timestamp_column_config_value(value: Any, field_name: str) -> str:
    timestamp_col = _string_config_value(value, field_name)
    if (
        timestamp_col != DEFAULT_TIMESTAMP_COLUMN
        and timestamp_col in REQUIRED_EVENT_COLUMNS
    ):
        raise ValueError(
            f"Config field '{field_name}' must not reuse an event field name: "
            f"{timestamp_col}."
        )
    return timestamp_col


def _int_config_value(value: Any, field_name: str, *, minimum: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"Config field '{field_name}' must be an integer.")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.strip().lstrip("+-").isdigit():
        parsed = int(value)
    else:
        raise ValueError(f"Config field '{field_name}' must be an integer.")

    if parsed < minimum:
        qualifier = "positive" if minimum == 1 else f"at least {minimum}"
        raise ValueError(f"Config field '{field_name}' must be {qualifier}.")
    return parsed


def _float_config_value(value: Any, field_name: str, *, minimum: float) -> float:
    if isinstance(value, bool):
        raise ValueError(f"Config field '{field_name}' must be a number.")
    if isinstance(value, (int, float)):
        parsed = float(value)
    elif isinstance(value, str):
        try:
            parsed = float(value.strip())
        except ValueError as exc:
            raise ValueError(f"Config field '{field_name}' must be a number.") from exc
    else:
        raise ValueError(f"Config field '{field_name}' must be a number.")

    if not math.isfinite(parsed):
        raise ValueError(f"Config field '{field_name}' must be a finite number.")
    if parsed < minimum:
        raise ValueError(f"Config field '{field_name}' must be at least {minimum:g}.")
    return parsed


def _normalize_optional_int(
    config: dict[str, Any],
    key: str,
    field_name: str,
    *,
    minimum: int,
) -> None:
    if key in config:
        config[key] = _int_config_value(config[key], field_name, minimum=minimum)


def _normalize_optional_float(
    config: dict[str, Any],
    key: str,
    field_name: str,
    *,
    minimum: float,
) -> None:
    if key in config:
        config[key] = _float_config_value(config[key], field_name, minimum=minimum)


def _optional_string_sequence(value: Any, field_name: str) -> list[str] | None:
    if value is None:
        return None
    return _string_sequence(value, field_name)


def _string_sequence(value: Any, field_name: str) -> list[str]:
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise ValueError(
            f"Config field '{field_name}' must be a list of non-empty strings."
        )

    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                f"Config field '{field_name}' must be a list of non-empty strings."
            )
        normalized.append(item.strip())
    return normalized


def _build_run_summary(
    input_path: Path,
    output_dir: Path,
    normalized: Any,
    windows: list[Any],
    features: Any,
    alerts: Any,
    cooldown_seconds: int,
    feature_path: Path,
    alert_path: Path,
    summary_path: Path,
    manifest_path: Path,
    plot_paths: list[Path],
) -> dict[str, object]:
    if alerts.empty:
        rule_counts: dict[str, int] = {}
    else:
        rule_counts = {
            str(rule_name): int(count)
            for rule_name, count in alerts["rule_name"].value_counts().sort_index().items()
        }

    artifact_paths = [
        feature_path,
        alert_path,
        summary_path,
        manifest_path,
        *plot_paths,
    ]

    return {
        "input_path": _display_path(input_path),
        "output_dir": _display_path(output_dir),
        "normalized_event_count": int(len(normalized)),
        "window_count": int(len(windows)),
        "feature_row_count": int(len(features)),
        "alert_count": int(len(alerts)),
        "triggered_rule_names": sorted(rule_counts),
        "triggered_rule_counts": rule_counts,
        "cooldown_seconds": int(cooldown_seconds),
        "generated_artifacts": [_display_path(path) for path in artifact_paths],
    }


if __name__ == "__main__":
    main()
