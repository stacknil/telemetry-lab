# AGENTS.md

## Working rules

- Inspect existing files before editing.
- Make minimal coherent changes.
- Prioritize an end-to-end runnable MVP over polish.
- Do not present the repo as production-ready.
- Run tests after code changes.

## Project focus

- Timestamped event streams
- Sliding-window aggregation
- Telemetry features
- Simple rule-based alerts
- Reproducible outputs from sample data

## Review guidelines

- Treat README and documentation mismatches against actual CLI/runtime behavior as high-priority findings.
- Check all input-format claims against the real loader implementation.
- Treat missing edge-case tests as important review findings when behavior depends on time parsing, window boundaries, or alert thresholds.
- Prefer correcting documentation to match real behavior unless the code path is accidental or deprecated.
- Flag alerting logic that is obviously too noisy for the bundled sample dataset.
- Prefer small, scoped fixes over broad refactors during PR review.
- Do not request production-grade features in a portfolio prototype unless the PR explicitly aims to add them.
- When reviewing plots, outputs, and examples, verify that referenced files and commands actually exist.
