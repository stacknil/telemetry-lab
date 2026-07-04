# What telemetry-lab v1.0 Freezes and Why It Is Not a SIEM

`telemetry-lab` v1.0 is a reviewer-contract release. Its purpose is to make a
small set of detection workflows reproducible and inspectable, not to turn the
repository into a monitoring platform.

That distinction matters because a growing demo repository can look like an
unfinished product. v1.0 closes that ambiguity by freezing the current review
surface.

## The five-demo contract

The [v1.0 release notes](release-v1.0.md) freeze five local, file-based demos:

1. telemetry windowing and alert features
2. bounded AI-assisted case drafting
3. rule evaluation and cooldown deduplication
4. configuration-change investigation
5. synthetic CloudTrail-like IAM investigation

The freeze covers committed synthetic inputs, reviewer-visible output paths,
JSON and JSONL schema contracts, reproducible artifacts, and the full test
suite. Adding a sixth demo is outside the v1.0 goal.

The point is not that every workflow has the same data model. The point is that
each workflow exposes its inputs, deterministic stages, evidence artifacts,
and boundaries in a stable place. The
[evidence pipeline contract](evidence-pipeline-contract.md) maps each
machine-readable artifact to its schema.

## What a reviewer can verify

The repository keeps generated CSV, JSON, JSONL, Markdown, and selected visual
artifacts under version control. A reviewer can regenerate the deterministic
artifacts, validate schema conformance, and run the tests:

```bash
python scripts/regenerate_artifacts.py --check
python -m pytest tests/test_evidence_pipeline_schemas.py
python -m pytest
```

The [operator reproduction guide](operator-reproduction.md) gives the ordered
path from a clean clone through all five demos. The
[contract freeze](v1-contract-freeze.md) explains which docs, schemas, tests,
and artifact names must change together when the contract changes.

## Why this is not a SIEM

The repository deliberately omits the platform surfaces that would make a
production SIEM claim meaningful:

- no real-time ingestion or streaming state
- no service deployment or dashboard
- no alert routing or case-management service
- no live cloud account integration
- no autonomous response
- no final incident verdict

The AI-assisted demo is bounded in the same way. Deterministic code performs
normalization, rule matching, grouping, and validation; the optional model role
is limited to structured case drafting that still requires human review.

## Why freezing is useful

A contract freeze makes external review cheaper. A reviewer can focus on
artifact regeneration, schema drift, time semantics, or documentation clarity
without first reverse-engineering a moving project boundary.

That is also why the next release line emphasizes operator reproduction and
issue triage rather than demo expansion. The portfolio signal is the quality of
the evidence path, not the number of dashboards or integrations it can imply.
