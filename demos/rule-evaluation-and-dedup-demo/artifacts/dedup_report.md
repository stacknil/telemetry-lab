# Rule Evaluation And Dedup Demo Report

This deterministic demo shows how repeated raw rule hits turn into fewer retained alerts after cooldown handling.
Cooldown keys are built from `(rule_name, scope)`, where scope prefers `entity`, then `source`, then `target`, then `host`, and falls back to rule-only dedup when none are present.

## Run Summary

- raw_rule_hits: 10
- retained_alerts: 6
- suppressed_hits: 4
- cooldown_seconds: 180

## Group Summary

| Rule / scope | Raw hits | Retained | Suppressed | First seen | Last seen |
| --- | ---: | ---: | ---: | --- | --- |
| login_fail_burst / entity=account:alice | 3 | 2 | 1 | 2026-03-18T10:01:00Z | 2026-03-18T10:04:30Z |
| login_fail_burst / entity=account:bob | 2 | 1 | 1 | 2026-03-18T10:01:20Z | 2026-03-18T10:02:00Z |
| high_error_rate / source=api-01 | 3 | 2 | 1 | 2026-03-18T10:05:00Z | 2026-03-18T10:08:30Z |
| rare_event_repeat_malware_alert / unscoped | 2 | 1 | 1 | 2026-03-18T10:07:00Z | 2026-03-18T10:08:00Z |

## Retained Alerts

- RH-001 kept for `login_fail_burst / entity=account:alice`; kept as the first hit for `login_fail_burst / entity=account:alice`.
  Represents suppressed duplicates: RH-002.
- RH-004 kept for `login_fail_burst / entity=account:bob`; kept as the first hit for `login_fail_burst / entity=account:bob`.
  Represents suppressed duplicates: RH-005.
- RH-003 kept for `login_fail_burst / entity=account:alice`; kept because 210 seconds elapsed since retained hit `RH-001`, which meets the 180 second cooldown.
- RH-006 kept for `high_error_rate / source=api-01`; kept as the first hit for `high_error_rate / source=api-01`.
  Represents suppressed duplicates: RH-007.
- RH-009 kept for `rare_event_repeat_malware_alert / unscoped`; kept as the first hit for `rare_event_repeat_malware_alert / unscoped`.
  Represents suppressed duplicates: RH-010.
- RH-008 kept for `high_error_rate / source=api-01`; kept because 210 seconds elapsed since retained hit `RH-006`, which meets the 180 second cooldown.

## Suppressed Hits

- RH-002 suppressed by RH-001 for `login_fail_burst / entity=account:alice`; suppressed because it matched the same cooldown key as retained hit `RH-001` only 40 seconds later, inside the 180 second cooldown.
- RH-005 suppressed by RH-004 for `login_fail_burst / entity=account:bob`; suppressed because it matched the same cooldown key as retained hit `RH-004` only 40 seconds later, inside the 180 second cooldown.
- RH-007 suppressed by RH-006 for `high_error_rate / source=api-01`; suppressed because it matched the same cooldown key as retained hit `RH-006` only 70 seconds later, inside the 180 second cooldown.
- RH-010 suppressed by RH-009 for `rare_event_repeat_malware_alert / unscoped`; suppressed because it matched the same cooldown key as retained hit `RH-009` only 60 seconds later, inside the 180 second cooldown.
