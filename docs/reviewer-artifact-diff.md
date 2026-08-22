# Reviewer-Facing Artifact Diff

Every release must include a concise artifact diff for reviewers. The diff
explains how committed outputs changed without asking reviewers to infer schema
or semantic changes from raw Git diffs. If no reviewer-facing artifact changed,
the release must say that explicitly with `no-artifact-change`.

This is a release-note contract, not a production migration guide. It applies to
the local, file-based artifacts listed in [`docs/reviewer-pack.md`](reviewer-pack.md)
and the schema-covered evidence artifacts in
[`docs/evidence-pipeline-contract.md`](evidence-pipeline-contract.md).

## Executable Triage Report

Use the standalone comparator when a regeneration mismatch needs more context:

```bash
python scripts/artifact_contract_diff.py \
  --expected path/to/committed-artifacts \
  --actual path/to/regenerated-artifacts \
  --json-out artifact-diff.json
```

The human summary and strict
[`artifact-contract-diff/v1`](../schemas/artifact_contract_diff.schema.json)
report expose missing, extra, and changed relative paths. JSON and JSONL entries
add record counts, top-level keys, exact schema/version markers, and run-manifest
digest fields when present. CSV, Markdown, text, JSON, and JSONL normalize CRLF
and CR to LF before comparison. Existing binary files are presence-only, so the
tool does not turn renderer-dependent PNG bytes into a reproducibility claim.

The report is deterministic: it contains no timestamp, artifact body, or
absolute checkout path. Exit status is `0` for no differences, `1` for contract
differences, and `2` for invalid or unreadable input. This tool explains a
mismatch; it does not replace `python scripts/regenerate_artifacts.py --check`,
accept regenerated output, or infer compatibility labels automatically.

Write `--json-out` outside both compared roots. The CLI rejects an output path
inside either tree and atomically replaces an existing external report only
after the new JSON has been written successfully.

### Report Semantics

| Field | Contract |
| --- | --- |
| `status` | `unchanged` requires an empty `differences` array; `changed` requires at least one difference. |
| `summary.*_files` | `expected_files = unchanged_files + missing_files + changed_files + presence_only_files`; the corresponding actual count substitutes `extra_files` for `missing_files`. |
| `unchanged_files` | Counts comparable text/JSON/JSONL files only. It does not include binaries checked for presence. |
| `differences[].status` | `missing` has only an expected snapshot, `extra` has only an actual snapshot, and `changed` has both. |
| `change_reasons` | Missing/extra use their single path reason. Changed comparable artifacts start with `content-changed` and may add structure, schema-version, or run-manifest-digest reasons. |
| `comparison_digest` | SHA-256 of the comparison bytes. Text-like artifacts use strict UTF-8 with CRLF and lone CR normalized to LF. |
| `comparison_size_bytes` | Length of those normalized comparison bytes, not necessarily the on-disk byte size. |
| `structure` | For changed, missing, or extra JSON/JSONL, records the container, record count, union of top-level keys, and validated schema/digest markers when present. |
| `presence_only_paths` | Sorted binary paths present in both trees. Their bytes are intentionally not compared or summarized. |

The local triage contract is bounded: each root may contain at most 10,000
files; structured summaries accept at most 64 MiB per changed JSON/JSONL file,
4,096 structural keys or schema markers, and 10,000 entries per run-manifest
digest map. Invalid digest shapes, unsafe embedded paths, symlinks, special
files, or exceeded limits fail closed with exit `2` and no JSON report.

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
