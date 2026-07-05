# Roadmap

Demo expansion is closed.

Next phase: v1 reviewer contract stabilization.

v1.1 theme: Operator Reproduction Release.

v1.2 theme: Architecture Cohesion Release.

The concrete milestone is [`v1.0 Five-Demo Contract Freeze`](v1-contract-freeze.md).

The repo now has five reviewer-verifiable demos and a clear [`docs/reviewer-path.md`](reviewer-path.md). The priority is to keep the demo matrix stable, preserve artifact names, keep release evidence explicit, and make review faster without implying a SIEM, dashboard, or production monitoring platform.

Recently added:

- [rule-evaluation-and-dedup-demo](../demos/rule-evaluation-and-dedup-demo/README.md) now shows raw rule hits, retained alerts, and suppression reasons side by side.
- [config-change-investigation-demo](../demos/config-change-investigation-demo/README.md) now shows risky configuration changes, bounded evidence attachment, and deterministic investigation summaries.
- [cloud-iam-change-investigation-demo](../demos/cloud-iam-change-investigation-demo/README.md) now shows synthetic CloudTrail-like IAM changes, bounded cloud-control-plane signals, and a small ATT&CK mapping set.
- [`docs/reviewer-path.md`](reviewer-path.md) maps common review questions to the right demo and artifacts.
- [`docs/reviewer-pack.md`](reviewer-pack.md) collects the top-level reviewer flow and artifact naming contract.
- [`docs/v1-contract-freeze.md`](v1-contract-freeze.md) defines the v1.0 five-demo contract freeze gate.
- [`docs/architecture.md`](architecture.md) describes the local file-based workflow shape.
- [`docs/vocabulary.md`](vocabulary.md) defines cross-demo evidence workflow terms.
- [`docs/reviewer-artifact-diff.md`](reviewer-artifact-diff.md) defines the release diff contract for reviewer-facing artifact changes.
- [`docs/v0.6-to-v1-artifact-diff.md`](v0.6-to-v1-artifact-diff.md) records the additive fourth-to-fifth-demo artifact contract.
- [`docs/operator-reproduction.md`](operator-reproduction.md) records the shortest clone-to-five-demo-verification path.
- [`docs/release-v1.1.md`](release-v1.1.md) records the operator reproduction and issue triage release.
- [`docs/release-v1.2.md`](release-v1.2.md) records the architecture cohesion release.
- [`docs/schema-compatibility-matrix.md`](schema-compatibility-matrix.md) records schema versions, artifact paths, and compatibility labels.
- `scripts/check_release_contract.py` wraps artifact regeneration, schema validation, and the full test suite.

## v1.2 Architecture Cohesion Release

The v1.2 release theme is architecture cohesion, not demo expansion.

Deliverable focus:

1. Resolve repository, package, and version identity: `telemetry-lab`, `telemetry_lab`, and `1.2.0`.
2. Establish the unified CLI: `telemetry-lab run window`, `telemetry-lab run ai-assisted`, `telemetry-lab run dedup`, `telemetry-lab run config-change`, `telemetry-lab run cloud-iam`, and `telemetry-lab verify`.
3. Generate `run_manifest.json` for each synthetic-local run with input and config digests.
4. Add property tests for window boundaries and dedup cooldown invariants.
5. Document notebooks as auxiliary exploration while the core pipeline remains headless.
6. Add a schema compatibility matrix for reviewer-facing JSON and JSONL artifacts.

## v1.1 Operator Reproduction Release

The v1.1 release theme is operator reproduction, not demo expansion.

Deliverable focus:

1. Keep the five-demo matrix unchanged.
2. Make clone-to-artifact-regeneration instructions short and explicit.
3. Provide issue templates for schema drift, artifact regeneration failures, demo boundary questions, and documentation reproduction questions.
4. Provide one reviewer-friendly release contract gate command.
5. Keep README verification commands copy/paste runnable.

## External Review Surface

Open review issues should stay sparse and tied to committed evidence. The
current public review entry should name one artifact, one schema, the expected
field-level output, and the acceptance criteria for a bounded documentation or
schema-contract correction.

Parked review directions:

- Clean-clone operator reproduction feedback, only when it names exact command
  output or a documentation mismatch.
- Synthetic edge-case additions, only when the input and expected artifact or
  schema rejection are already bounded to one existing demo.
- Human-verification boundary examples, only when they use existing committed
  artifacts and do not imply an incident verdict or production workflow.

## v1.2 Blocker

- Before tagging v1.2, confirm package identity remains aligned across
  repository metadata, `pyproject.toml`, console scripts, docs, and tests.

## v1 Reviewer Contract Stabilization

1. Stabilize the demo matrix.
2. Treat v1.0 as a five-demo contract freeze, not a feature expansion.
3. Freeze reviewer-visible artifact names unless a rename is intentional and documented across README, reviewer docs, demo docs, tests, and sample outputs.
4. Keep JSON schema contracts aligned with reviewer-facing JSON and JSONL evidence artifacts across the five-demo matrix.
5. Keep committed evidence artifacts aligned with regenerated pipeline output through `python scripts/regenerate_artifacts.py --check`.
6. Keep cross-demo vocabulary stable for evidence workflow terms.
7. Include reviewer-facing artifact diffs in every release, including explicit `no-artifact-change` notes when committed reviewer artifacts are unchanged.
8. Keep one top-level reviewer pack as the primary no-guessing entrypoint.
9. Keep the architecture diagram aligned with actual CLI and artifact behavior.
10. Prefer regression tests and documentation accuracy over adding new workflow surface area.

The consolidation gate lives in [`docs/v1-readiness-gate.md`](v1-readiness-gate.md).

## Demo Expansion Closed

The optional final demo slot has been used by `cloud-iam-change-investigation-demo`.

Further work should focus on reviewer contract stability, documentation accuracy, tests, and committed artifact reproducibility rather than adding more workflow surface area.

## Non-Directions

- No production monitoring claims
- No realtime ingestion or streaming state
- No dashboard or service deployment
- No alert routing or case management
- No autonomous response
