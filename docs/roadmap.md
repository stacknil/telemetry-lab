# Roadmap

`telemetry-lab` is moving from demo expansion toward v0.7 / v1.0 consolidation.

The repo now has five reviewer-verifiable demos and a clear [`docs/reviewer-path.md`](reviewer-path.md). The priority is to keep the demo matrix stable, preserve artifact names, and make review faster without implying a SIEM, dashboard, or production monitoring platform.

Recently added:

- [rule-evaluation-and-dedup-demo](../demos/rule-evaluation-and-dedup-demo/README.md) now shows raw rule hits, retained alerts, and suppression reasons side by side.
- [config-change-investigation-demo](../demos/config-change-investigation-demo/README.md) now shows risky configuration changes, bounded evidence attachment, and deterministic investigation summaries.
- [cloud-iam-change-investigation-demo](../demos/cloud-iam-change-investigation-demo/README.md) now shows synthetic CloudTrail-like IAM changes, bounded cloud-control-plane signals, and a small ATT&CK mapping set.
- [`docs/reviewer-path.md`](reviewer-path.md) maps common review questions to the right demo and artifacts.
- [`docs/reviewer-pack.md`](reviewer-pack.md) collects the top-level reviewer flow and artifact naming contract.
- [`docs/architecture.md`](architecture.md) describes the local file-based workflow shape.

## v0.7 / v1.0 Consolidation

1. Stabilize the demo matrix.
2. Freeze reviewer-visible artifact names unless a rename is intentional and documented across README, reviewer docs, demo docs, tests, and sample outputs.
3. Keep one top-level reviewer pack as the primary no-guessing entrypoint.
4. Keep the architecture diagram aligned with actual CLI and artifact behavior.
5. Prefer regression tests and documentation accuracy over adding new workflow surface area.

The consolidation gate lives in [`docs/reviewer-pack.md`](reviewer-pack.md#v1-readiness-gate).

## Final Demo Slot

The optional final demo slot is now used by `cloud-iam-change-investigation-demo`.

Further work before v1-style consolidation should focus on stability, documentation accuracy, tests, and committed artifact reproducibility rather than adding more workflow surface area.

## Non-Directions

- No production monitoring claims
- No realtime ingestion or streaming state
- No dashboard or service deployment
- No alert routing or case management
- No autonomous response
