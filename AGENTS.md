# AGENTS.md

## Working rules

- Inspect existing files before editing.
- Make minimal coherent changes.
- Prefer small, reviewable pull requests.
- Prioritize correctness, reproducibility, and README accuracy over polish.
- Do not present the repo as production-ready.

## Build and test

- Install: `python -m pip install -e .`
- Test: `pytest`
- Demo run: `python -m telemetry_window_demo.cli run --config configs/default.yaml`

## Review guidelines

- Treat README or docs mismatches against actual CLI/runtime behavior as important findings.
- Check input-format claims against the real loader implementation.
- Treat missing edge-case tests as important findings when behavior depends on time parsing, window boundaries, or alert thresholds.
- Flag alerting logic that is obviously too noisy for the bundled sample dataset.
- Prefer small, scoped fixes over broad refactors during review.
- Verify that referenced commands, files, and output artifacts actually exist.
