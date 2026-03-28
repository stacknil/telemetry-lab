# AI-Assisted Detection Demo Report

This report is analyst-facing draft output from a constrained case summarization pipeline.
Detections and grouping are deterministic. The LLM is limited to structured summarization only.
Human verification is required. No automated response actions or final incident verdicts are produced.

## Run Integrity

- accepted_rules: AUTH-001, AUTH-002, PROC-001, WEB-001
- rejected_rules: none
- coverage_degraded: no
- rejection_reasons: none

## CASE-001

- Severity: high
- First seen: 2026-03-27T09:01:55Z
- Last seen: 2026-03-27T09:02:20Z
- Rule hits: repeated_failed_logins, successful_login_after_failures
- ATT&CK: T1110, T1078

Summary: CASE-001 contains 2 deterministic rule hits covering repeated_failed_logins, successful_login_after_failures for principal ops_admin; src_ip 198.51.100.24; host vpn-gw-01 during 2026-03-27T09:01:55Z to 2026-03-27T09:02:20Z. The case warrants analyst review but does not imply a final incident decision.

Likely causes:
- Repeated password guessing or credential stuffing against the targeted account.
- A valid credential may have been used after several failed login attempts.

Uncertainty notes:
- Telemetry is limited to the bundled sample evidence and does not confirm operator intent.
- The case summary is advisory only and requires human review before any incident classification.

Suggested next steps:
- Review the raw evidence and confirm whether the activity aligns with an approved administrative task.
- Check authentication context for MFA state, prior successful logins, and expected source locations.
- Document the analyst conclusion separately after human verification; do not treat this summary as a final verdict.

## CASE-002

- Severity: medium
- First seen: 2026-03-27T09:11:10Z
- Last seen: 2026-03-27T09:11:10Z
- Rule hits: sensitive_path_scan
- ATT&CK: T1595

Summary: CASE-002 contains 1 deterministic rule hits covering sensitive_path_scan for src_ip 203.0.113.77; host portal-01 during 2026-03-27T09:11:10Z to 2026-03-27T09:11:10Z. The case warrants analyst review but does not imply a final incident decision.

Likely causes:
- The source IP appears to be probing sensitive web paths on the exposed application.

Uncertainty notes:
- Telemetry is limited to the bundled sample evidence and does not confirm operator intent.
- The case summary is advisory only and requires human review before any incident classification.
- Prompt-like text appeared in telemetry and was treated strictly as untrusted evidence.

Suggested next steps:
- Review the raw evidence and confirm whether the activity aligns with an approved administrative task.
- Compare the web requests with reverse-proxy and WAF logs to determine whether the probing continued.
- Document the analyst conclusion separately after human verification; do not treat this summary as a final verdict.

## CASE-003

- Severity: high
- First seen: 2026-03-27T09:20:00Z
- Last seen: 2026-03-27T09:20:20Z
- Rule hits: encoded_powershell_execution, encoded_powershell_execution
- ATT&CK: T1059.001

Summary: CASE-003 contains 2 deterministic rule hits covering encoded_powershell_execution for principal lab_user; host wkstn-07 during 2026-03-27T09:20:00Z to 2026-03-27T09:20:20Z. The case warrants analyst review but does not imply a final incident decision.

Likely causes:
- Obfuscated PowerShell execution may reflect manual tradecraft or an unsafe script.

Uncertainty notes:
- Telemetry is limited to the bundled sample evidence and does not confirm operator intent.
- The case summary is advisory only and requires human review before any incident classification.

Suggested next steps:
- Review the raw evidence and confirm whether the activity aligns with an approved administrative task.
- Inspect the originating host timeline and validate whether the encoded PowerShell command matches known tooling.
- Document the analyst conclusion separately after human verification; do not treat this summary as a final verdict.
