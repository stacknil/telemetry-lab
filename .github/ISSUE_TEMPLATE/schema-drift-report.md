---
name: Schema drift report
about: Report a mismatch between a reviewer-facing JSON/JSONL artifact and its schema
title: "[Schema drift]: "
labels: ["schema", "reviewer-contract"]
---

## Artifact

Path:

Schema:

## Command

```bash
python -m pytest tests/test_evidence_pipeline_schemas.py
```

## Failure

Paste the failing schema validation path and message.

## Expected Contract

Describe which schema field or artifact path appears out of sync.

## Boundary Check

- [ ] This report is about committed synthetic reviewer artifacts only.
- [ ] This is not a request for live ingestion, production detection, dashboard, alert routing, or case management.
- [ ] No real account IDs, credentials, hostnames, or private data are included.
