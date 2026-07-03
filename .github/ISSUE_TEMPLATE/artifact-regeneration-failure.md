---
name: Artifact regeneration failure
about: Report a failure in the committed artifact regeneration gate
title: "[Artifact regeneration]: "
labels: ["artifacts", "reviewer-contract"]
---

## Command

```bash
python scripts/regenerate_artifacts.py --check
```

## Failure Summary

Paste the failing job, artifact path, reason, and exit code.

## Environment

- OS:
- Python version:
- Fresh clone or existing checkout:

## Expected Contract

The committed artifact should match deterministic local output, or the drift
should be documented in a reviewer-facing artifact diff.

## Boundary Check

- [ ] This report uses only the committed synthetic sample data.
- [ ] No live AWS account, production telemetry, credentials, or private data are involved.
- [ ] This is not a request for a dashboard, SIEM, alert routing, case management, or autonomous response.
