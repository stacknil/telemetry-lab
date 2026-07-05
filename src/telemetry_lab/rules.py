from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
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
    rules_config: Mapping[str, Any] | None = None,
) -> pd.DataFrame:
    config = _rules_mapping(rules_config)
    cooldown_seconds = _int_option(
        config,
        "cooldown_seconds",
        0,
        label="cooldown_seconds",
        minimum=0,
    )
    high_error_rate_config = _rule_mapping(config, "high_error_rate")
    login_fail_burst_config = _rule_mapping(config, "login_fail_burst")
    high_severity_spike_config = _rule_mapping(config, "high_severity_spike")
    persistent_high_error_config = _rule_mapping(config, "persistent_high_error")
    source_spread_spike_config = _rule_mapping(config, "source_spread_spike")
    rare_event_repeat_config = _rule_mapping(config, "rare_event_repeat")

    if features.empty:
        return pd.DataFrame(columns=ALERT_COLUMNS)

    alerts: list[dict[str, object]] = []

    alerts.extend(_high_error_rate_alerts(features, high_error_rate_config))
    alerts.extend(_login_fail_burst_alerts(features, login_fail_burst_config))
    alerts.extend(_high_severity_spike_alerts(features, high_severity_spike_config))
    alerts.extend(
        _persistent_high_error_alerts(
            features,
            persistent_high_error_config,
        )
    )
    alerts.extend(_source_spread_spike_alerts(features, source_spread_spike_config))
    alerts.extend(_rare_event_repeat_alerts(features, rare_event_repeat_config))

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
    rule: Mapping[str, Any],
) -> list[dict[str, object]]:
    threshold = _float_option(
        rule,
        "threshold",
        0.30,
        label="high_error_rate.threshold",
        minimum=0.0,
    )
    severity = _string_option(
        rule,
        "severity",
        "medium",
        label="high_error_rate.severity",
    )
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
    rule: Mapping[str, Any],
) -> list[dict[str, object]]:
    column = event_count_column("login_fail")
    if column not in features.columns:
        return []

    threshold = _int_option(
        rule,
        "threshold",
        10,
        label="login_fail_burst.threshold",
        minimum=1,
    )
    severity = _string_option(
        rule,
        "severity",
        "high",
        label="login_fail_burst.severity",
    )
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
    rule: Mapping[str, Any],
) -> list[dict[str, object]]:
    threshold = _int_option(
        rule,
        "threshold",
        3,
        label="high_severity_spike.threshold",
        minimum=1,
    )
    severity = _string_option(
        rule,
        "severity",
        "high",
        label="high_severity_spike.severity",
    )
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
    rule: Mapping[str, Any],
) -> list[dict[str, object]]:
    threshold = _float_option(
        rule,
        "threshold",
        0.25,
        label="persistent_high_error.threshold",
        minimum=0.0,
    )
    consecutive_windows = _int_option(
        rule,
        "consecutive_windows",
        2,
        label="persistent_high_error.consecutive_windows",
        minimum=1,
    )
    severity = _string_option(
        rule,
        "severity",
        "medium",
        label="persistent_high_error.severity",
    )

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
    rule: Mapping[str, Any],
) -> list[dict[str, object]]:
    absolute_threshold = _int_option(
        rule,
        "absolute_threshold",
        10,
        label="source_spread_spike.absolute_threshold",
        minimum=1,
    )
    multiplier = _float_option(
        rule,
        "multiplier",
        1.5,
        label="source_spread_spike.multiplier",
        minimum=1.0,
    )
    severity = _string_option(
        rule,
        "severity",
        "medium",
        label="source_spread_spike.severity",
    )

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
    rule: Mapping[str, Any],
) -> list[dict[str, object]]:
    threshold = _int_option(
        rule,
        "threshold",
        2,
        label="rare_event_repeat.threshold",
        minimum=1,
    )
    severity = _string_option(
        rule,
        "severity",
        "high",
        label="rare_event_repeat.severity",
    )
    event_types = _string_sequence_option(
        rule,
        "event_types",
        label="rare_event_repeat.event_types",
    )

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


def _rules_mapping(rules_config: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if rules_config is None:
        return {}
    if not isinstance(rules_config, Mapping):
        raise ValueError("Rules config must be a mapping.")
    return rules_config


def _rule_mapping(config: Mapping[str, Any], rule_name: str) -> Mapping[str, Any]:
    value = config.get(rule_name, {})
    if not isinstance(value, Mapping):
        raise ValueError(f"Rules config '{rule_name}' must be a mapping.")
    return value


def _int_option(
    config: Mapping[str, Any],
    key: str,
    default: int,
    *,
    label: str,
    minimum: int,
) -> int:
    value = config.get(key, default)
    if isinstance(value, bool):
        raise ValueError(f"Rules config '{label}' must be an integer.")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.strip().lstrip("+-").isdigit():
        parsed = int(value)
    else:
        raise ValueError(f"Rules config '{label}' must be an integer.")

    if parsed < minimum:
        qualifier = "positive" if minimum == 1 else f"at least {minimum}"
        raise ValueError(f"Rules config '{label}' must be {qualifier}.")
    return parsed


def _float_option(
    config: Mapping[str, Any],
    key: str,
    default: float,
    *,
    label: str,
    minimum: float,
) -> float:
    value = config.get(key, default)
    if isinstance(value, bool):
        raise ValueError(f"Rules config '{label}' must be a number.")
    if isinstance(value, (int, float)):
        parsed = float(value)
    elif isinstance(value, str):
        try:
            parsed = float(value.strip())
        except ValueError as exc:
            raise ValueError(f"Rules config '{label}' must be a number.") from exc
    else:
        raise ValueError(f"Rules config '{label}' must be a number.")

    if not math.isfinite(parsed):
        raise ValueError(f"Rules config '{label}' must be a finite number.")
    if parsed < minimum:
        raise ValueError(f"Rules config '{label}' must be at least {minimum:g}.")
    return parsed


def _string_option(
    config: Mapping[str, Any],
    key: str,
    default: str,
    *,
    label: str,
) -> str:
    value = config.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Rules config '{label}' must be a non-empty string.")
    return value.strip()


def _string_sequence_option(
    config: Mapping[str, Any],
    key: str,
    *,
    label: str,
) -> list[str]:
    value = config.get(key, [])
    if isinstance(value, str) or not isinstance(value, Sequence):
        raise ValueError(
            f"Rules config '{label}' must be a list of non-empty strings."
        )

    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                f"Rules config '{label}' must be a list of non-empty strings."
            )
        normalized.append(item.strip())
    return normalized
