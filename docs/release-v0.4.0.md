# v0.4.0 — second demo and portfolio integration

This is a small portfolio milestone release for `telemetry-lab`.

The repository now presents a two-demo structure:

| Demo | Role |
| --- | --- |
| `telemetry-window-demo` | Windowed telemetry analysis with deterministic rules, CSV outputs, and timeline artifacts |
| `ai-assisted-detection-demo` | Deterministic detection and case grouping with constrained LLM summarization and auditable rejection paths |

## What changed

### Repo structure and front door

- The landing page now presents `telemetry-lab` as a two-demo repository
- The top-level README includes direct navigation to both demos
- The public repo story is now easier to scan from the landing page

### New second demo

- Added `ai-assisted-detection-demo`
- The demo centers on:
  - deterministic detection
  - deterministic case grouping
  - constrained LLM summarization
  - audit traces and visible rejection paths

### Guardrails and boundaries

- `human_verification` is required
- No autonomous response actions
- No final incident verdict
- No LLM-driven detection or grouping decisions
- Fail-closed validation remains in place for invalid or disallowed outputs

### Reviewer-facing documentation

- Added a walkthrough for:
  - accepted summary path
  - rejected summary path
  - degraded coverage path
- Added an explicit lifecycle contract and audit schema version in the design documentation

## Why this milestone matters

This release moves `telemetry-lab` from a single-demo prototype toward a clearer portfolio repository with:

- one telemetry/windowing workflow
- one case-centric, AI-assisted investigation workflow
- explicit guardrails around model output and operator review

## Validation

- Full test suite: `43 passed`

## Notes

This is a portfolio milestone release, not a product launch.
The repository remains intentionally scoped to small, reviewable prototypes.
