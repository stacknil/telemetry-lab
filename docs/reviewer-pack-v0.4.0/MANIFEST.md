# v0.4.0 Reviewer Pack Manifest

This pack is a small, sanitized reviewer artifact set for `ai-assisted-detection-demo`.

It is intended for release attachment or offline review. The files are portable, contain no secrets, and are scoped to the demo's public portfolio story rather than production operations.

| File | Path Proven | Source Type | What It Proves |
| --- | --- | --- | --- |
| `accepted-summary-example.json` | accepted summary path | sanitized excerpt from committed demo artifacts | An accepted summary is bound to a real case, keeps `human_verification = required`, and is recorded as `accepted` in the audit record |
| `rejected-summary-example.json` | rejected summary path | representative sanitized example aligned with tests | Invalid model output is rejected fail-closed, omitted from accepted summaries, and still recorded in the audit trail |
| `degraded-coverage-example.json` | degraded coverage path | representative sanitized example aligned with tests | Rule metadata failure reduces coverage safely and is surfaced in both run-integrity reporting and audit output |

