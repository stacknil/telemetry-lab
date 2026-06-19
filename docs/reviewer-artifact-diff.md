# Reviewer-Facing Artifact Diff

Every release must include a concise artifact diff for reviewers. The diff
explains how committed outputs changed without asking reviewers to infer schema
or semantic changes from raw Git diffs. If no reviewer-facing artifact changed,
the release must say that explicitly with `no-artifact-change`.

This is a release-note contract, not a production migration guide. It applies to
the local, file-based artifacts listed in [`docs/reviewer-pack.md`](reviewer-pack.md)
and the schema-covered evidence artifacts in
[`docs/evidence-pipeline-contract.md`](evidence-pipeline-contract.md).

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
