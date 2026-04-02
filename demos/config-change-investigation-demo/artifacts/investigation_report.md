# Config-Change Investigation Demo Report

This deterministic demo correlates risky configuration changes with bounded follow-on evidence.
It does not use an LLM and does not produce autonomous response actions.

## Run Summary

- normalized_change_events: 4
- risky_change_hits: 3
- investigations: 3
- correlation_window_minutes: 15

## CCI-001

- Severity: critical
- Target system: identity-proxy
- Triggering change: cfg-001 (disable_admin_mfa -> true)
- Trigger reason: Admin MFA was disabled on a protected system.
- Attached policy denials: 2
- Attached follow-on events: 2
- Bounded correlation: Attached evidence shares target_system 'identity-proxy' and falls within 15 minutes after the triggering change.

Policy denials:
- den-001: admin-login-guard -> MFA policy blocked admin login after configuration drift.
- den-002: token-exchange-guard -> Token exchange blocked after admin-auth policy divergence.

Follow-on events:
- fo-001: auth_fail_burst -> 5 privileged login failures from 203.0.113.24 after the config change.
- fo-002: service_restart -> identity-proxy restarted after an auth-policy reload.

## CCI-002

- Severity: high
- Target system: payments-api
- Triggering change: cfg-002 (public_bind_cidr -> 0.0.0.0/0)
- Trigger reason: Public bind CIDR was expanded to all addresses.
- Attached policy denials: 1
- Attached follow-on events: 2
- Bounded correlation: Attached evidence shares target_system 'payments-api' and falls within 15 minutes after the triggering change.

Policy denials:
- den-003: public-exposure-guard -> Public bind CIDR exceeded the approved network range.

Follow-on events:
- fo-003: service_restart -> payments-api restarted after listener rebind.
- fo-004: edge_warning -> Edge listener observed requests from the newly public CIDR.

## CCI-003

- Severity: high
- Target system: vault-gateway
- Triggering change: cfg-004 (break_glass_mode -> enabled)
- Trigger reason: Break-glass mode was enabled on a sensitive service.
- Attached policy denials: 0
- Attached follow-on events: 0
- Bounded correlation: Attached evidence shares target_system 'vault-gateway' and falls within 15 minutes after the triggering change.

No nearby supporting evidence fell inside the bounded correlation window.
