from __future__ import annotations

import argparse
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
from .preprocess import normalize_events
from .rules import apply_rules
from .visualize import plot_outputs
from .windowing import build_windows


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="telemetry-window-demo",
        description="Windowed telemetry analytics on timestamped event streams.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run the full telemetry pipeline.")
    run_parser.add_argument("--config", required=True, help="Path to a YAML config file.")
    run_parser.set_defaults(func=run_command)

    summarize_parser = subparsers.add_parser(
        "summarize",
        help="Summarize an input event file.",
    )
    summarize_parser.add_argument("--input", required=True, help="Path to .jsonl or .csv.")
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

    return parser


def run_command(args: argparse.Namespace) -> None:
    config_path = Path(args.config).resolve()
    config = load_config(config_path)
    time_config = config.get("time", {})
    feature_config = config.get("features", {})
    rules_config = config.get("rules") or {}
    input_path = resolve_config_path(config_path, config["input_path"])
    output_dir = resolve_config_path(config_path, config.get("output_dir", "data/processed"))

    events = load_events(input_path)
    normalized = normalize_events(
        events,
        timestamp_col=time_config.get("timestamp_col", "timestamp"),
        error_statuses=feature_config.get("error_statuses"),
        high_severity_levels=feature_config.get("severity_levels"),
    )
    windows = build_windows(
        normalized,
        timestamp_col=time_config.get("timestamp_col", "timestamp"),
        window_size_seconds=int(time_config.get("window_size_seconds", 60)),
        step_size_seconds=int(time_config.get("step_size_seconds", 10)),
    )
    features = compute_window_features(
        normalized,
        windows,
        count_event_types=feature_config.get("count_event_types"),
    )
    alerts = apply_rules(features, rules_config)
    cooldown_seconds = int(rules_config.get("cooldown_seconds", 0))

    feature_path = write_table(features, output_dir / "features.csv")
    alert_path = write_table(alerts, output_dir / "alerts.csv")
    plot_paths = plot_outputs(features, alerts, output_dir)
    summary_path = output_dir / "summary.json"
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
        plot_paths=plot_paths,
    )
    write_json(summary, summary_path)

    print(f"[OK] Loaded {len(normalized)} events")
    print(f"[OK] Generated {len(features)} windows")
    print(f"[OK] Computed {max(len(features.columns) - 2, 0)} features per window")
    print(f"[OK] Triggered {len(alerts)} alerts")
    print(f"[OK] Saved {feature_path.name}, {alert_path.name}")
    print(f"[OK] Saved plots to {_display_path(output_dir)}")
    for plot_path in plot_paths:
        print(f"     - {plot_path.name}")


def summarize_command(args: argparse.Namespace) -> None:
    events = normalize_events(load_events(args.input))
    min_time = format_timestamp(events["timestamp"].min())
    max_time = format_timestamp(events["timestamp"].max())
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

    demo_root = Path(args.demo_root).resolve() if args.demo_root else default_demo_root()
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

    demo_root = Path(args.demo_root).resolve() if args.demo_root else default_demo_root()
    result = run_demo(demo_root=demo_root)

    print(f"[OK] Loaded {result['raw_hit_count']} raw rule hits")
    print(f"[OK] Retained {result['retained_alert_count']} alerts")
    print(f"[OK] Suppressed {result['suppressed_hit_count']} repeated hits")
    print(f"[OK] Evaluated {result['group_count']} rule/scope groups")
    print(f"[OK] Saved artifacts to {_display_path(result['artifacts_dir'])}")
    for name, path in result["artifacts"].items():
        print(f"     - {name}: {_display_path(path)}")


def _display_path(path: Path) -> str:
    cwd = Path.cwd().resolve()
    resolved = path.resolve()
    try:
        return resolved.relative_to(cwd).as_posix()
    except ValueError:
        return resolved.as_posix()


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
