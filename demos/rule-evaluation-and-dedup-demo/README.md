# Rule Evaluation And Dedup Demo

This demo is part of `telemetry-lab` and is intentionally small, local, and reviewer-friendly.

It focuses on alert semantics, not new AI behavior. The sample input is a committed set of raw rule hits that already fired before deduplication. The demo then applies deterministic cooldown handling and writes artifacts that explain which hits were kept, which were suppressed, and why.

## Purpose

The goal is to make repeated alert behavior legible.

Instead of only showing the final retained alerts, this demo shows:

- raw rule hits before deduplication
- retained alerts after cooldown handling
- per-hit suppression reasons
- a short report that explains how repeated hits collapsed into fewer alerts

## Quick Start

From the repository root:

```bash
python -m pip install -e .
python -m telemetry_window_demo.cli run-rule-dedup-demo
```

Generated artifacts are written to `demos/rule-evaluation-and-dedup-demo/artifacts/`.

## Demo Inputs

- sample data: `data/raw/sample_rule_hits.json`
- cooldown config: `config/dedup.yaml`

The bundled sample intentionally includes:

- repeated hits for the same rule and `entity`
- repeated hits for the same rule and `source`
- repeated hits with no scope fields, which fall back to rule-only dedup
- different scopes for the same rule, which stay independent

## Cooldown Semantics

Cooldown keys use `(rule_name, scope)`.

Scope resolution follows the same precedence described in the main demo:

1. `entity`
2. `source`
3. `target`
4. `host`
5. unscoped rule-only fallback

That means repeated hits for the same rule can still be kept separately when their scopes differ.

## Expected Artifacts

- `artifacts/rule_hits_before_dedup.json`
- `artifacts/rule_hits_after_dedup.json`
- `artifacts/dedup_explanations.json`
- `artifacts/dedup_report.md`

## Artifact Semantics

- `rule_hits_before_dedup.json`: normalized raw hits with resolved cooldown scope and cooldown key
- `rule_hits_after_dedup.json`: only the retained alerts, including which suppressed hits each retained alert now represents
- `dedup_explanations.json`: one explanation record per raw hit, marked as either `retained` or `suppressed`
- `dedup_report.md`: a short reviewer-facing report with run counts, per-group summary, retained alert explanations, and suppressed hit reasons

## Reviewer Walkthrough

1. Open `rule_hits_before_dedup.json` and note that several hits share the same `cooldown_key`.
2. Open `dedup_explanations.json` and verify that each raw hit is labeled `retained` or `suppressed` with a concrete reason.
3. Open `rule_hits_after_dedup.json` and confirm that retained alerts carry the suppressed hit ids they now represent.
4. Open `dedup_report.md` and confirm that the before/after counts and per-group behavior are readable without looking at code.

## Limitations

- input is precomputed rule hits, not live telemetry
- cooldown logic is intentionally simple and deterministic
- there is no streaming state, dashboard, or service deployment
- artifacts are designed for review, not production alert routing
