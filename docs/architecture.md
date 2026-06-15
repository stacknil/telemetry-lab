# Architecture

`telemetry-lab` is a local, file-based detection workflow lab. It is organized around committed sample inputs, deterministic demo pipelines, and reviewer-facing artifacts.

```mermaid
flowchart TD
    Inputs["Committed sample inputs<br/>JSONL, CSV, YAML configs"]
    CLI["Local CLI entrypoints<br/>run, run-ai-demo, run-rule-dedup-demo, run-config-change-demo, run-cloud-iam-change-demo"]
    Window["telemetry-window-demo<br/>normalize -> windows -> features -> alerts"]
    AI["ai-assisted-detection-demo<br/>rules -> cases -> JSON-only drafting"]
    Dedup["rule-evaluation-and-dedup-demo<br/>raw hits -> cooldown -> suppression reasons"]
    Config["config-change-investigation-demo<br/>config changes -> bounded evidence correlation"]
    CloudIAM["cloud-iam-change-investigation-demo<br/>CloudTrail-like events -> IAM change signals"]
    Artifacts["Reviewer artifacts<br/>CSV, JSON, JSONL, Markdown, PNG"]
    Review["Reviewer inspection<br/>README, reviewer path, reviewer pack, tests"]

    Inputs --> CLI
    CLI --> Window
    CLI --> AI
    CLI --> Dedup
    CLI --> Config
    CLI --> CloudIAM
    Window --> Artifacts
    AI --> Artifacts
    Dedup --> Artifacts
    Config --> Artifacts
    CloudIAM --> Artifacts
    Artifacts --> Review
```

## Design Rules

- Detection decisions stay deterministic and inspectable.
- The AI-assisted demo is limited to bounded JSON-only case drafting.
- Artifacts are file-based and suitable for local regeneration or GitHub review.
- Artifact names are reviewer-visible contracts during the v1 reviewer contract stabilization phase.
- The repository does not provide production monitoring, real-time ingestion, dashboards, alert routing, case management, autonomous response, or final incident verdicts.

## Demo Boundaries

| Demo | Boundary |
| --- | --- |
| `telemetry-window-demo` | Converts raw events into window features and alerts; does not become a live stream processor. |
| `ai-assisted-detection-demo` | Drafts constrained summaries from deterministic cases; does not decide incident outcomes or call tools. |
| `rule-evaluation-and-dedup-demo` | Explains cooldown and suppression behavior; does not route alerts. |
| `config-change-investigation-demo` | Correlates risky changes with bounded local evidence; does not monitor live infrastructure. |
| `cloud-iam-change-investigation-demo` | Reviews synthetic CloudTrail-like IAM and cloud-control-plane signals; does not connect to AWS or assert incident verdicts. |
