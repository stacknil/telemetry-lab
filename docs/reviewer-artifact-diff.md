# Reviewer-Facing Artifact Diff

Every release must include a concise artifact diff for reviewers. The diff
explains how committed outputs changed without asking reviewers to infer schema
or semantic changes from raw Git diffs. If no reviewer-facing artifact changed,
the release must say that explicitly with `no-artifact-change`.

This is a release-note contract, not a production migration guide. It applies to
the local, file-based artifacts listed in [`docs/reviewer-pack.md`](reviewer-pack.md)
and the schema-covered evidence artifacts in
[`docs/evidence-pipeline-contract.md`](evidence-pipeline-contract.md).

## Executable Human Triage

Use the standalone comparator when a regeneration mismatch needs path-level
context:

```bash
python scripts/artifact_contract_diff.py \
  --expected path/to/committed-artifacts \
  --actual path/to/regenerated-artifacts
```

Add a strict machine-readable projection when automation or an attached review
artifact needs the same semantics:

```bash
python scripts/artifact_contract_diff.py \
  --expected path/to/committed-artifacts \
  --actual path/to/regenerated-artifacts \
  --json-out path/outside-both-trees/artifact-diff.json
```

The output lists missing, extra, and changed relative paths in stable order.
CSV, Markdown, text, JSON, and JSONL use strict UTF-8 and normalize CRLF and
lone CR to LF before comparison. A binary path that exists in both trees is
checked for presence only; renderer-dependent bytes are not treated as a
reproducibility contract.

For changed, missing, or extra JSON and JSONL, the comparator builds a bounded
summary of the container, record count, top-level keys, safe schema/version
markers, and validated run-manifest digest fields. Those summaries distinguish
plain content changes from structure, schema-version, and provenance-digest
changes. Identical JSON and JSONL are not parsed after their normalized bytes
match. Artifact bodies are never printed.

The optional JSON output conforms to
[`artifact-contract-diff/v1`](../schemas/artifact_contract_diff.schema.json).
It contains no timestamp, checkout root, or artifact body, so repeated runs on
the same trees are byte-identical. The destination must resolve outside both
input roots. A new report is written in the destination directory and atomically
replaces an older report only after serialization and file synchronization
succeed; a comparison or write failure leaves an existing report unchanged.

Exit status is `0` when comparable artifacts are unchanged, `1` when the tool
finds contract differences, and `2` when an input cannot be compared safely.
The output contains no artifact bodies, timestamps, or absolute checkout paths.
This tool explains a mismatch; it does not replace
`python scripts/regenerate_artifacts.py --check`, accept regenerated output, or
assign a release compatibility label.

Each root is limited to 10,000 files. A structured summary accepts at most 64
MiB of normalized content, 4,096 top-level keys, 4,096 schema markers, and
10,000 entries per run-manifest digest map. Symlink or reparse-point roots,
linked entries, special files, unsafe relative paths or metadata, malformed
digest fields, unreadable files, invalid JSON/JSONL, exceeded limits, and
invalid UTF-8 text fail closed with exit `2`.

### JSON Report Semantics

| Field | Contract |
| --- | --- |
| `status` | `unchanged` requires no differences; `changed` requires at least one. |
| `summary` | Counts expected, actual, unchanged, missing, extra, changed, and presence-only files. Core report invariants reconcile these counts. |
| `differences[].status` | `missing` has only an expected snapshot, `extra` has only an actual snapshot, and `changed` has both. |
| `change_reasons` | Missing and extra use one path reason. Changed comparable artifacts begin with `content-changed` and may add structure, schema-version, or run-manifest-digest reasons. |
| `comparison_digest` | SHA-256 of comparison bytes; text-like artifacts use normalized strict UTF-8 bytes. |
| `comparison_size_bytes` | Length of the comparison bytes, which may differ from the on-disk size after newline normalization. |
| `structure` | Present only for summarized JSON/JSONL snapshots. |
| `presence_only_paths` | Sorted binary paths present in both trees; their bytes are not compared or reported. |

## Required Release Diff Sections

Each release artifact diff must include:

- **Added fields**: new reviewer-visible fields, columns, Markdown sections, or
  schema properties.
- **Removed fields**: deleted or renamed reviewer-visible fields, columns,
  Markdown sections, or schema properties.
- **Semantic changes**: meaning changes for existing fields, including changes
  to ordering, grouping, correlation bounds, severity meaning, summary counts,
  or report interpretation.
- **Compatibility notes**: whether existing reviewer checks, example outputs,
  schemas, or downstream inspection scripts need updates.

If a release does not change reviewer-facing artifacts, state that explicitly.
Do not leave the diff section blank.

## Compatibility Labels

Use one of these labels per changed artifact:

| Label | Meaning |
| --- | --- |
| `no-artifact-change` | The release does not change reviewer-facing artifact content or meaning. |
| `additive-compatible` | Fields or sections were added without changing existing field meaning. |
| `semantic-change` | Existing fields remain present, but their meaning, ordering, grouping, or counting changed. |
| `breaking-artifact-change` | Fields were removed, renamed, or changed in a way that requires reviewer docs, schemas, or checks to change. |
| `non-contract-artifact` | The artifact is intentionally reviewer-visible but not part of the JSON schema contract. |

## Template

Use this table in release notes or release reviewer packs:

| Artifact | Added fields | Removed fields | Semantic changes | Compatibility notes |
| --- | --- | --- | --- | --- |
| `path/to/artifact.json` | `field_name`, or `none` | `field_name`, or `none` | Short description, or `none` | `additive-compatible`, `semantic-change`, `breaking-artifact-change`, `no-artifact-change`, or `non-contract-artifact` |

For broad changes, group related artifacts by demo but keep one row per
reviewer-visible artifact whose shape or meaning changed.

## Review Rules

- Cover every changed stable reviewer-visible artifact from
  [`docs/reviewer-pack.md`](reviewer-pack.md#stable-reviewer-visible-artifacts).
- Cover every changed schema-covered artifact from
  [`docs/evidence-pipeline-contract.md`](evidence-pipeline-contract.md#schema-matrix).
- Include a `no-artifact-change` statement for docs-only, test-only, or
  refactor-only releases that do not alter committed reviewer artifacts.
- Mention artifact renames as both a removed artifact path and an added artifact
  path, then explain compatibility.
- Keep the language reviewer-facing: describe what changed in the evidence a
  reviewer inspects, not internal implementation details.
- Preserve the repo boundary: do not describe changes as SIEM, dashboard,
  alert-routing, case-management, autonomous response, or final-verdict features.

## Example

| Artifact | Added fields | Removed fields | Semantic changes | Compatibility notes |
| --- | --- | --- | --- | --- |
| `demos/example/artifacts/example_summary.json` | `artifact_generated_at` | `none` | `none` | `additive-compatible`; reviewers can ignore the new timestamp field if they only inspect counts. |
| `demos/example/artifacts/example_report.md` | `Compatibility notes` section | `none` | Report now separates raw evidence counts from retained findings. | `semantic-change`; reviewer docs and tests should point to the new section. |
