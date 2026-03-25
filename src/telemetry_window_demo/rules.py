from __future__ import annotations

from typing import Any

import pandas as pd

from .schema import event_count_column

ALERT_COLUMNS = (
    "alert_time",
    "rule_name",
    "severity",
    "window_start",
    "window_end",
    "message",
)
COOLDOWN_SCOPE_COLUMNS = ("entity", "source", "target", "host")


def apply_rules(
    features: pd.DataFrame,
    rules_config: dict[str, Any] | None = None,
) -> pd.DataFrame:
    if features.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    config = rules_config or {}
    cooldown_seconds = int(config.get("cooldown_seconds", 0))
    alerts: list[dict[str, object]] = []

    alerts.extend(_high_error_rate_alerts(features, config.get("high_error_rate", {})))
    alerts.extend(_login_fail_burst_alerts(features, config.get("login_fail_burst", {})))
    alerts.extend(
        _high_severity_spike_alerts(features, config.get("high_severity_spike", {}))
    )
    alerts.extend(
        _persistent_high_error_alerts(
            features,
            config.get("persistent_high_error", {}),
        )
    )
    alerts.extend(
        _source_spread_spike_alerts(features, config.get("source_spread_spike", {}))
    )
    alerts.extend(_rare_event_repeat_alerts(features, config.get("rare_event_repeat", {})))

    if not alerts:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    alerts_frame = pd.DataFrame(alerts)
    alerts_frame = alerts_frame.sort_values(["alert_time", "rule_name"]).reset_index(drop=True)
    return _apply_alert_cooldown(alerts_frame, cooldown_seconds)


def _row_alert(
    row: pd.Series,
    rule_name: str,
    severity: str,
    message: str,
    cooldown_scope: str | None = None,
) -> dict[str, object]:
    return {
        "alert_time": row["window_end"],
        "rule_name": rule_name,
        "severity": severity,
        "window_start": row["window_start"],
        "window_end": row["window_end"],
        "message": message,
        "cooldown_scope": _resolve_cooldown_scope(row, cooldown_scope),
    }


def _resolve_cooldown_scope(
    row: pd.Series,
    explicit_scope: str | None = None,
) -> str | None:
    if explicit_scope is not None:
        value = explicit_scope.strip()
        if value:
            return value

    for column in COOLDOWN_SCOPE_COLUMNS:
        if column not in row.index:
            continue

        value = row[column]
        if pd.isna(value):
            continue

        value_text = str(value).strip()
        if value_text:
            return f"{column}={value_text}"

    return None


def _apply_alert_cooldown(
    alerts: pd.DataFrame,
    cooldown_seconds: int,
) -> pd.DataFrame:
    if alerts.empty or cooldown_seconds <= 0:
        return alerts.loc[:, ALERT_COLUMNS].reset_index(drop=True)

    last_kept_at: dict[tuple[str, str | None], pd.Timestamp] = {}
    kept_rows: list[int] = []

    for index, row in alerts.iterrows():
        rule_name = str(row["rule_name"])
        alert_time = pd.Timestamp(row["alert_time"])
        scope_value = row.get("cooldown_scope")
        if pd.isna(scope_value):
            scope = None
        else:
            scope_text = str(scope_value).strip()
            scope = scope_text or None

        cooldown_key = (rule_name, scope)
        last_alert_time = last_kept_at.get(cooldown_key)

        if last_alert_time is None:
            kept_rows.append(index)
            last_kept_at[cooldown_key] = alert_time
            continue

        elapsed = (alert_time - last_alert_time).total_seconds()
        if elapsed >= cooldown_seconds:
            kept_rows.append(index)
            last_kept_at[cooldown_key] = alert_time

    return alerts.loc[kept_rows, ALERT_COLUMNS].reset_index(drop=True)


def _high_error_rate_alerts(
    features: pd.DataFrame,
    rule: dict[str, Any],
) -> list[dict[str, object]]:
    threshold = float(rule.get("threshold", 0.30))
    severity = str(rule.get("severity", "medium"))
    matches = features[features["error_rate"] > threshold]
    return [
        _row_alert(
            row,
            "high_error_rate",
            severity,
            f"error_rate {row['error_rate']:.2f} exceeded {threshold:.2f}",
        )
        for _, row in matches.iterrows()
    ]


def _login_fail_burst_alerts(
    features: pd.DataFrame,
    rule: dict[str, Any],
) -> list[dict[str, object]]:
    column = event_count_column("login_fail")
    if column not in features.columns:
        return []

    threshold = int(rule.get("threshold", 10))
    severity = str(rule.get("severity", "high"))
    matches = features[features[column] >= threshold]
    return [
        _row_alert(
            row,
            "login_fail_burst",
            severity,
            f"{column} reached {int(row[column])}, threshold is {threshold}",
        )
        for _, row in matches.iterrows()
    ]


def _high_severity_spike_alerts(
    features: pd.DataFrame,
    rule: dict[str, Any],
) -> list[dict[str, object]]:
    threshold = int(rule.get("threshold", 3))
    severity = str(rule.get("severity", "high"))
    matches = features[features["high_severity_count"] >= threshold]
    return [
        _row_alert(
            row,
            "high_severity_spike",
            severity,
            f"high_severity_count reached {int(row['high_severity_count'])}",
        )
        for _, row in matches.iterrows()
    ]


def _persistent_high_error_alerts(
    features: pd.DataFrame,
    rule: dict[str, Any],
) -> list[dict[str, object]]:
    threshold = float(rule.get("threshold", 0.25))
    consecutive_windows = int(rule.get("consecutive_windows", 2))
    severity = str(rule.get("severity", "medium"))

    alerts: list[dict[str, object]] = []
    streak = 0
    for _, row in features.iterrows():
        if row["error_rate"] > threshold:
            streak += 1
            if streak >= consecutive_windows:
                alerts.append(
                    _row_alert(
                        row,
                        "persistent_high_error",
                        severity,
                        (
                            f"error_rate stayed above {threshold:.2f} for "
                            f"{consecutive_windows} windows"
                        ),
                    )
                )
        else:
            streak = 0
    return alerts


def _source_spread_spike_alerts(
    features: pd.DataFrame,
    rule: dict[str, Any],
) -> list[dict[str, object]]:
    absolute_threshold = int(rule.get("absolute_threshold", 10))
    multiplier = float(rule.get("multiplier", 1.5))
    severity = str(rule.get("severity", "medium"))

    alerts: list[dict[str, object]] = []
    previous_sources: int | None = None
    for _, row in features.iterrows():
        current_sources = int(row["unique_sources"])
        if previous_sources and previous_sources > 0:
            ratio = current_sources / previous_sources
            if current_sources >= absolute_threshold and ratio >= multiplier:
                alerts.append(
                    _row_alert(
                        row,
                        "source_spread_spike",
                        severity,
                        (
                            f"unique_sources rose from {previous_sources} to "
                            f"{current_sources} ({ratio:.2f}x)"
                        ),
                    )
                )
        previous_sources = current_sources
    return alerts


def _rare_event_repeat_alerts(
    features: pd.DataFrame,
    rule: dict[str, Any],
) -> list[dict[str, object]]:
    threshold = int(rule.get("threshold", 2))
    severity = str(rule.get("severity", "high"))
    event_types = list(rule.get("event_types", []))

    alerts: list[dict[str, object]] = []
    for event_type in event_types:
        column = event_count_column(event_type)
        if column not in features.columns:
            continue

        matches = features[features[column] >= threshold]
        for _, row in matches.iterrows():
            alerts.append(
                _row_alert(
                    row,
                    f"rare_event_repeat_{event_type}",
                    severity,
                    f"{event_type} repeated {int(row[column])} times in one window",
                )
            )
    return alerts

