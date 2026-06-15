# Cloud IAM Change Investigation Demo

This demo is part of `telemetry-lab` and stays intentionally small, local, and reviewer-friendly.

It uses synthetic CloudTrail-like events to show bounded investigation logic around IAM and nearby cloud-control-plane changes. It does not connect to AWS and does not produce a final incident verdict.

## Purpose

The goal is to make one compact CloudTrail-style investigation path legible from committed sample data.

The demo starts from one JSONL file, then:

- validates a CloudTrail-like event skeleton
- normalizes events into deterministic internal records
- applies five bounded investigation rules
- attaches a small ATT&CK mapping set for reviewer orientation
- writes machine-readable summaries and a short reviewer-facing report

## Quick Start

From the repository root:

```bash
python -m pip install -e .
python -m telemetry_window_demo.cli run-cloud-iam-change-demo
```

Generated artifacts are written to `demos/cloud-iam-change-investigation-demo/artifacts/`.

## Demo Input

- events: `data/raw/synthetic_cloudtrail_like_events.jsonl`
- investigation config: `config/investigation.yaml`

Every input record includes this CloudTrail-like skeleton:

- `eventTime`
- `userIdentity`
- `eventSource`
- `eventName`
- `awsRegion`
- `sourceIPAddress`
- `userAgent`
- `errorCode`
- `requestParameters`
- `responseElements`
- `eventID`

Optional input fields:

- `observedTime`

## Time Model

- `eventTime` is normalized to `event_time` and drives sorting, bounded correlation, and signal timing.
- optional `observedTime` is preserved as `observed_time` when present, but it is not used for detection ordering.
- committed artifacts avoid `artifact_generated_at` so the demo output remains deterministic across local reruns.

AWS CloudTrail documentation describes event record contents for who made a request, the service and action, request parameters, response data, errors, source IP, user agent, Region, time, and event ID. This demo uses a synthetic subset of that shape for local review only.

Reference:

- [AWS CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)

## Rules

The deterministic rules are:

- failed console login burst
- new access key creation after failed logins
- policy attachment after unusual source IP
- CloudTrail logging disabled near IAM change
- security group ingress opened after identity change

## ATT&CK Mapping

The config intentionally keeps the mapping set small:

- [Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [Account Manipulation: Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
- [Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/)
- [Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)

These mappings are reviewer context, not a verdict.

## Expected Artifacts

- `artifacts/normalized_cloudtrail_events.json`
- `artifacts/investigation_signals.json`
- `artifacts/investigation_summary.json`
- `artifacts/investigation_report.md`

## Expected Run Summary

The bundled sample run should report:

- `14` normalized CloudTrail-like events
- `5` evaluated investigation rules
- `5` investigation signals
- `5` ATT&CK mapping entries

## Reviewer Walkthrough

1. Open `synthetic_cloudtrail_like_events.jsonl` and verify the CloudTrail-like fields are synthetic placeholders.
2. Open `normalized_cloudtrail_events.json` and confirm the sample was normalized without adding external context.
3. Open `investigation_signals.json` and inspect which event IDs each bounded rule attached.
4. Open `investigation_summary.json` and confirm the boundaries remain explicit.
5. Open `investigation_report.md` and verify the report stays reviewer-facing, not incident-final.

## Boundaries

- synthetic CloudTrail-like events only
- no live AWS account
- no real account ID
- no production detection claim
- no final incident verdict
- no SIEM, dashboard, alert routing, case-management, realtime ingestion, or autonomous response
