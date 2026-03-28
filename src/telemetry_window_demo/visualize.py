from __future__ import annotations

from pathlib import Path

import matplotlib
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def plot_outputs(
    features: pd.DataFrame,
    alerts: pd.DataFrame,
    output_dir: str | Path,
) -> list[Path]:
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    plt.style.use("seaborn-v0_8-whitegrid")
    paths = [
        _plot_metric(
            features,
            target_dir / "event_count_timeline.png",
            metric="event_count",
            title="Event Count Over Time",
            ylabel="Event count",
        ),
        _plot_metric(
            features,
            target_dir / "error_rate_timeline.png",
            metric="error_rate",
            title="Error Rate Over Time",
            ylabel="Error rate",
            alerts=alerts,
        ),
        _plot_alert_timeline(
            alerts,
            target_dir / "alerts_timeline.png",
        ),
    ]
    return paths


def _plot_metric(
    features: pd.DataFrame,
    output_path: Path,
    metric: str,
    title: str,
    ylabel: str,
    alerts: pd.DataFrame | None = None,
) -> Path:
    figure, axis = plt.subplots(figsize=(11, 4.5))
    if features.empty:
        axis.text(0.5, 0.5, "No feature windows generated", ha="center", va="center")
        axis.set_axis_off()
    else:
        axis.plot(
            features["window_end"],
            features[metric],
            color="#114B5F",
            linewidth=2.0,
            marker="o",
            markersize=3,
        )
        axis.set_title(title)
        axis.set_xlabel("Window end")
        axis.set_ylabel(ylabel)

        if alerts is not None and not alerts.empty:
            rate_alerts = alerts[alerts["rule_name"].str.contains("error", na=False)]
            if not rate_alerts.empty:
                highlighted = features.merge(
                    rate_alerts[["window_end"]].drop_duplicates(),
                    on="window_end",
                    how="inner",
                )
                axis.scatter(
                    highlighted["window_end"],
                    highlighted[metric],
                    color="#C1121F",
                    s=42,
                    zorder=3,
                    label="alert window",
                )
                axis.legend(frameon=False)

        figure.autofmt_xdate()

    figure.tight_layout()
    figure.savefig(output_path, dpi=160)
    plt.close(figure)
    return output_path


def _plot_alert_timeline(alerts: pd.DataFrame, output_path: Path) -> Path:
    figure, axis = plt.subplots(figsize=(11, 4.5))
    if alerts.empty:
        axis.text(0.5, 0.5, "No alerts triggered", ha="center", va="center")
        axis.set_axis_off()
    else:
        severities = {
            "low": "#4D908E",
            "medium": "#F4A261",
            "high": "#E63946",
            "critical": "#6A040F",
        }
        rule_positions = {
            rule_name: index for index, rule_name in enumerate(alerts["rule_name"].unique())
        }
        y_values = alerts["rule_name"].map(rule_positions)
        colors = alerts["severity"].map(lambda value: severities.get(value, "#264653"))

        axis.scatter(
            alerts["alert_time"],
            y_values,
            c=colors,
            s=90,
            edgecolor="white",
            linewidth=0.8,
        )
        axis.set_yticks(list(rule_positions.values()), list(rule_positions.keys()))
        axis.set_xlabel("Alert time")
        axis.set_title("Alerts on Timeline")
        figure.autofmt_xdate()

    figure.tight_layout()
    figure.savefig(output_path, dpi=160)
    plt.close(figure)
    return output_path
