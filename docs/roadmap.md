# Roadmap

This repository is intentionally small, so the next steps should be new demos that make the existing telemetry pipeline easier to understand rather than a broad platform build-out.

Recently added:

- [rule-evaluation-and-dedup-demo](../demos/rule-evaluation-and-dedup-demo/README.md) now shows raw rule hits, retained alerts, and suppression reasons side by side.
- [config-change-investigation-demo](../demos/config-change-investigation-demo/README.md) now shows risky configuration changes, bounded evidence attachment, and deterministic investigation summaries.

## 1. Auth/Login Anomaly Triage Demo

Goal:
Add a demo that walks from bursty login failures into follow-on signals such as source spread, eventual success, or repeated target concentration.

Why it helps the portfolio:
This strengthens the repo's analyst-facing story. It shows how simple window features and rule output can support a concrete triage narrative instead of stopping at generic alert generation.

## 2. Config-Change Drift Follow-Up Demo

Goal:
Add a compact follow-up scenario centered on repeated config drift, rollback attempts, and evidence that the remediation path actually reduced nearby denials or noisy follow-on signals.

Why it helps the portfolio:
This would build on the current config-change investigation demo without changing the repo's local, file-based character. It would show not just the initial risky change, but also how deterministic evidence can support a short remediation narrative.
