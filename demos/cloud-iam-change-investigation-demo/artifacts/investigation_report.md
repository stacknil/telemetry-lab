# Cloud IAM Change Investigation Demo Report

This deterministic demo reviews synthetic CloudTrail-like events for bounded IAM and cloud-control-plane signals.
It uses no live AWS account, no real account IDs, no realtime ingestion, and no final incident verdict.

## Run Summary

- source_type: synthetic CloudTrail-like JSONL
- normalized_events: 14
- investigation_signals: 5
- attack_mapping_count: 5

## Signals

### CTI-001 - failed console login burst

- Severity: medium
- Actor: USER_A
- Primary event: evt-cti-003
- Evidence event IDs: evt-cti-001, evt-cti-002, evt-cti-003
- ATT&CK mapping: Brute Force: Password Spraying, Valid Accounts: Cloud Accounts
- Bounded reason: 3 failed ConsoleLogin events for USER_A fell inside a 5 minute window.
- Scope: synthetic reviewer signal only; no production claim or final verdict

### CTI-002 - new access key creation after failed logins

- Severity: high
- Actor: USER_A
- Primary event: evt-cti-005
- Evidence event IDs: evt-cti-001, evt-cti-002, evt-cti-003, evt-cti-005
- ATT&CK mapping: Account Manipulation: Additional Cloud Credentials, Valid Accounts: Cloud Accounts
- Bounded reason: CreateAccessKey for USER_A occurred after 3 failed console login event(s) inside 15 minutes.
- Scope: synthetic reviewer signal only; no production claim or final verdict

### CTI-003 - policy attachment after unusual source IP

- Severity: high
- Actor: USER_A
- Primary event: evt-cti-006
- Evidence event IDs: evt-cti-006
- ATT&CK mapping: Valid Accounts: Cloud Accounts
- Bounded reason: AttachUserPolicy came from 203.0.113.45, which is not in the demo's expected source IP list.
- Scope: synthetic reviewer signal only; no production claim or final verdict

### CTI-004 - CloudTrail logging disabled near IAM change

- Severity: critical
- Actor: USER_A
- Primary event: evt-cti-007
- Evidence event IDs: evt-cti-005, evt-cti-006, evt-cti-007
- ATT&CK mapping: Disable or Modify Cloud Log, Valid Accounts: Cloud Accounts
- Bounded reason: StopLogging occurred within 10 minutes of 2 IAM change event(s).
- Scope: synthetic reviewer signal only; no production claim or final verdict

### CTI-005 - security group ingress opened after identity change

- Severity: high
- Actor: USER_A
- Primary event: evt-cti-008
- Evidence event IDs: evt-cti-005, evt-cti-006, evt-cti-008
- ATT&CK mapping: Modify Cloud Compute Infrastructure, Valid Accounts: Cloud Accounts
- Bounded reason: AuthorizeSecurityGroupIngress opened a world-routable range after 2 IAM change event(s) inside 15 minutes.
- Scope: synthetic reviewer signal only; no production claim or final verdict

## Boundaries

- Synthetic CloudTrail-like events only
- No live AWS account
- No real account ID
- No production detection claim
- No final incident verdict
