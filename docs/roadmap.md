# Roadmap

This repository is intentionally small, so the next steps should be new demos that make the existing telemetry pipeline easier to understand rather than a broad platform build-out.

Recently added:

- [rule-evaluation-and-dedup-demo](../demos/rule-evaluation-and-dedup-demo/README.md) now shows raw rule hits, retained alerts, and suppression reasons side by side.

## 1. Auth/Login Anomaly Triage Demo

Goal:
Add a demo that walks from bursty login failures into follow-on signals such as source spread, eventual success, or repeated target concentration.

Why it helps the portfolio:
This strengthens the repo's analyst-facing story. It shows how simple window features and rule output can support a concrete triage narrative instead of stopping at generic alert generation.

## 2. Config-Change Investigation Demo

Goal:
Add a compact scenario centered on risky configuration changes, follow-on policy denials, and a short machine-readable investigation summary.

Why it helps the portfolio:
This broadens the repo beyond auth-only behavior while staying inside the same local, file-based pipeline. It gives the project a second clear demo narrative that is still easy to explain from committed sample data.
