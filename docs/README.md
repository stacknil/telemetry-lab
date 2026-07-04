# telemetry-lab docs

This directory separates the current reviewer route from supporting design notes and historical release evidence. The repo is a local, file-based detection workflow lab, not a SIEM, dashboard, or production monitoring platform.

## Current reviewer route

- [`reviewer-pack.md`](reviewer-pack.md): top-level reviewer pack, demo matrix, artifact naming contract, and v1 readiness gate
- [`operator-reproduction.md`](operator-reproduction.md): shortest local path from clone to verifying all five demos
- [`reviewer-path.md`](reviewer-path.md): choose a demo by review question
- [`reviewer-brief.md`](reviewer-brief.md): short problem, value, evidence, and boundary summary
- [`v1-contract-freeze.md`](v1-contract-freeze.md): v1.0 five-demo contract freeze, release status, and contract scope
- [`v1-readiness-gate.md`](v1-readiness-gate.md): fixed inputs, fixed outputs, schema validation, artifact regeneration, and test pass requirements
- [`release-v1.0.md`](release-v1.0.md): v1.0 reviewer-contract release notes with the explicit non-SIEM boundary
- [`release-v1.1.md`](release-v1.1.md): v1.1 operator reproduction and issue triage release notes
- [`v0.6-to-v1-artifact-diff.md`](v0.6-to-v1-artifact-diff.md): additive artifact contract and compatibility diff from the fourth demo to the fifth
- [`evidence-pipeline-contract.md`](evidence-pipeline-contract.md): JSON/JSONL schema contracts for reviewer-facing evidence artifacts
- [`reviewer-artifact-diff.md`](reviewer-artifact-diff.md): release diff contract for reviewer-facing artifact changes
- [`vocabulary.md`](vocabulary.md): cross-demo vocabulary for evidence workflow terms and bounded correlation
- [`architecture.md`](architecture.md): local file-based workflow diagram
- [`roadmap.md`](roadmap.md): v1 reviewer contract stabilization phase

## Supporting docs

- [`sample-output.md`](sample-output.md): committed output counts and sample artifacts
- [`event-time-model.md`](event-time-model.md): event, observed, window, and artifact time semantics
- [`design-notes.md`](design-notes.md): original telemetry-window design boundaries
- [`ai-assisted-detection-design.md`](ai-assisted-detection-design.md): bounded AI-assisted detection design
- [`ai-assisted-detection-examples.md`](ai-assisted-detection-examples.md): example AI-assisted detection outputs and guardrail behavior
- [`ai-assisted-detection-reviewer-pack.md`](ai-assisted-detection-reviewer-pack.md): reviewer pack for the AI-assisted demo
- [`config-change-investigation-demo-design.md`](config-change-investigation-demo-design.md): config-change investigation design notes
- [`config-change-investigation-reviewer-pack.md`](config-change-investigation-reviewer-pack.md): reviewer pack for the config-change investigation demo

## Historical release evidence

These files are retained as release evidence snapshots. Use the current reviewer route above for the maintained review path.

- [`release-v0.4.0.md`](release-v0.4.0.md)
- [`reviewer-pack-v0.4.0/MANIFEST.md`](reviewer-pack-v0.4.0/MANIFEST.md)
- [`reviewer-pack-v0.6.0/MANIFEST.md`](reviewer-pack-v0.6.0/MANIFEST.md)
