# From Saved Linux Process Evidence to Reproducible Telemetry Aggregation

*A bounded, file-based producer–consumer integration case study · 19 October 2026*

## The engineering question

Can a saved Linux process/socket evidence workflow produce an event stream that a separate telemetry application can consume **without changing either implementation or silently upgrading evidence into security conclusions**?

This case study exercises two existing projects at fixed public commits:

| Role | Repository | Commit |
| --- | --- | --- |
| Producer | [stacknil/systems-foundations](https://github.com/stacknil/systems-foundations/tree/1d31d4287036cf2bbd3aeb8059d7d332bedef598) (`linux-process-observe`) | [`1d31d4287036cf2bbd3aeb8059d7d332bedef598`](https://github.com/stacknil/systems-foundations/commit/1d31d4287036cf2bbd3aeb8059d7d332bedef598) |
| Consumer | [stacknil/telemetry-lab](https://github.com/stacknil/telemetry-lab/tree/98ae3ffd1edb47d90eb42b3a8625be830582997e) (`run window`) | [`98ae3ffd1edb47d90eb42b3a8625be830582997e`](https://github.com/stacknil/telemetry-lab/commit/98ae3ffd1edb47d90eb42b3a8625be830582997e) |

The experiment uses only committed synthetic procfs and `ss` fixtures. It does not collect live host information.

## Pipeline and contract

`saved procfs + ss fixtures → two snapshots → directional diff → seven JSONL observations → telemetry-lab window aggregation`

The producer's adapter emits UTF-8 JSONL records with `timestamp`, `event_type`, `source`, `target`, and `status`, plus evidence metadata. The record types include `process_added`, `process_removed`, `process_modified`, `socket_link_added`, and `socket_link_removed`. The consumer already accepts JSONL with those required fields; no custom ingestion adapter was added. See the [producer workflow and adapter contract](https://github.com/stacknil/systems-foundations/blob/1d31d4287036cf2bbd3aeb8059d7d332bedef598/projects/linux-process-observe/README.md) and [consumer input contract](https://github.com/stacknil/telemetry-lab/blob/98ae3ffd1edb47d90eb42b3a8625be830582997e/README.md#input-support).

One field requires particular care. All seven change records have `timestamp = 2026-07-05T00:05:00Z` and `metadata.time_semantics = snapshot_diff_observed_at`. This is **the comparison-observation timestamp** of the after snapshot, not a measurement of when each process/socket change occurred. The consumer preserves the metadata but uses the supplied `timestamp` for window membership; it does not derive occurrence times from that marker. The resulting window is therefore an *observation-time comparison window*.

The `source` field is a process snapshot identifier of the form `host_id:pid:start_time_ticks`, not an IP address or an authenticated actor. It is a same-boot snapshot identity without a boot identifier, not an independently verified process instance or cross-reboot identity. Executable paths and socket endpoint strings in `target` are contextual descriptions; retained metadata does not certify their authenticity.

## Reproduction path

The reported execution used two fresh HTTPS clones at the exact commits above, a separate Windows 11 / CPython 3.12.14 runtime, and disposable outputs. The following sequence summarizes the actual private command receipts, from the pinned `projects/linux-process-observe` directory; it is not a fresh-environment installation transcript. Four unmodified producer CLI operations generated the data:

1. `snapshot` with `--proc-root tests/fixtures/baseline/proc`, `--ss tests/fixtures/baseline/ss.txt`, `--host-id lab-host` and `--observed-at 2026-07-05T00:00:00Z`.
2. `snapshot` with `--proc-root tests/fixtures/changed/proc`, `--ss tests/fixtures/changed/ss.txt`, `--host-id lab-host` and `--observed-at 2026-07-05T00:05:00Z`.
3. `diff` using both process snapshots and both socket-link artifacts.
4. `adapt` using the generated `process_diff.json` to write `telemetry_events.jsonl`.

These commands and their argument contracts are documented in the [pinned process-lab README](https://github.com/stacknil/systems-foundations/blob/1d31d4287036cf2bbd3aeb8059d7d332bedef598/projects/linux-process-observe/README.md#workflow). In the observed run, all four commands exited `0`. Each input snapshot contained four processes and four process/socket links.

The actual consumer operation was `telemetry-lab run window --config <disposable-config>`. This public transcription substitutes an illustrative path for the private config location:

```sh
telemetry-lab run window --config path/to/disposable-integration.yaml
```

The disposable YAML started with [the pinned default configuration](https://github.com/stacknil/telemetry-lab/blob/98ae3ffd1edb47d90eb42b3a8625be830582997e/configs/default.yaml). Only two configuration values changed:

```yaml
input_path: /absolute/path/to/generated/telemetry_events.jsonl
output_dir: /absolute/path/to/disposable/consumer-output
```

All time, feature, rule, threshold and cooldown settings remained at their defaults. The two-line YAML fragment shows replacements in a full copy of the default config, not a complete standalone configuration. These path values and the command's config location are illustrative placeholders, not the private paths actually executed or files published with this article. The [`run window` workflow](https://github.com/stacknil/telemetry-lab/blob/98ae3ffd1edb47d90eb42b3a8625be830582997e/README.md#quick-run) is the actual consumer entry point. A fresh dependency install from the public internet was **not** established by this experiment: after an incomplete initial setup, the verified run used an isolated environment with read-only reuse of compatible, already installed dependency files. Both pinned project packages were installed locally, and `pip check` succeeded.

## Observed results

| Check | Observed result |
| --- | --- |
| Producer output against committed golden files | **7/7 byte-identical** |
| Producer adapter output | **7 JSONL change records** |
| Consumer input records loaded / normalized | **7 / 7** |
| Observation-time windows | **1** |
| Numeric features in the window | **11** |
| `event_count`, distinct `source`, distinct `target` | **7 / 4 / 7** |
| Default-rule alerts | **0** |
| Summary and run-manifest schema validation | **2/2 passed** |
| Second consumer run, identical paths/runtime/config | **7/7 output files byte-identical**, including three PNG files |

The sole window was the half-open interval `[2026-07-05T00:05:00Z, 2026-07-05T00:06:00Z)`. All seven records belonged to it. The normalized rows retained their event types, contextual source/target identifiers and nested evidence metadata; aggregate feature CSVs are not per-record provenance ledgers.

The generated producer JSONL retained for this run was 4,108 bytes and matched the [public, pinned golden JSONL](https://github.com/stacknil/systems-foundations/blob/1d31d4287036cf2bbd3aeb8059d7d332bedef598/projects/linux-process-observe/tests/golden/diff/telemetry_events.jsonl) byte-for-byte, with SHA-256:

```text
1977b98518497c9a07da6393499cb49e6d0be9140ac5bcd708c2a1cd31a3ad51
```

The consumer's `run-manifest/v2` identified the file under `external/input/telemetry_events.jsonl` and the disposable configuration under `external/config/integration.yaml`. Its per-file input/config fingerprints matched the exact file bytes; the legacy aggregate digests were checked separately using their label and text-normalization contract. These fingerprints support content identification, **not** signatures, cryptographic source authentication or chain-of-custody certification.

### Why zero alerts is the correct observation

The adapter expresses changes using statuses such as `added`, `removed`, and `modified`. The consumer's unchanged default error-status set is `fail`/`blocked`, while its event-specific counters target login, configuration, malware, and policy-event categories—not these process/socket change categories. Consequently the observed `error_count` and those category counters were zero, and none of the configured alert predicates fired. The events were still ingested and counted.

**Seven events → one observation window → zero alerts** is an accurate integration result. It is neither a positive detection test nor evidence that the synthetic changes are benign.

## What this demonstrates—and what it does not

This bounded run establishes that two separately developed file-based components can interoperate at the stated commits, preserve required event/evidence fields through normalization, produce the expected window aggregates, and regenerate seven consumer artifacts byte-for-byte on the **same Windows/Python runtime and paths**. Producer outputs also match the committed goldens byte-for-byte.

It does **not** establish live Linux collection, event occurrence chronology, measured bursts, atomic procfs/`ss` acquisition, authenticity of saved inputs, independent execution-instance attribution, cross-reboot identity, detection efficacy, production SIEM compatibility, or byte-for-byte equivalence of plotted PNGs across operating systems or dependency versions. No additional pytest-suite result is attributed to this integration run.

The engineering lesson is a boundary discipline: make data interfaces executable and reproducible while keeping **observation, aggregation, detection and provenance claims** distinct. An interoperable telemetry pipeline is useful even when the correct detector output is zero.

## Evidence availability

The pinned implementations, synthetic fixtures and producer goldens are public. The generated execution outputs and full Stage 12 receipts remain privately retained and are not published with this article. The result table summarizes those retained outputs; the public golden alone does not prove that the consumer execution occurred. The earlier public Issue #6 evidence concerns the producer-only workflow, not this consumer integration.

## Public references

- [Producer documentation and saved-fixture commands](https://github.com/stacknil/systems-foundations/blob/1d31d4287036cf2bbd3aeb8059d7d332bedef598/projects/linux-process-observe/README.md)
- [Producer golden artifacts](https://github.com/stacknil/systems-foundations/tree/1d31d4287036cf2bbd3aeb8059d7d332bedef598/projects/linux-process-observe/tests/golden)
- [Earlier producer-only clean-clone reproduction, Issue #6](https://github.com/stacknil/systems-foundations/issues/6#issuecomment-6262009302)
- [Consumer README and default rules](https://github.com/stacknil/telemetry-lab/blob/98ae3ffd1edb47d90eb42b3a8625be830582997e/README.md)
- [Consumer event-time model](https://github.com/stacknil/telemetry-lab/blob/98ae3ffd1edb47d90eb42b3a8625be830582997e/docs/event-time-model.md)

*Prepared from the retained 19 October 2026 integration evidence. No engineering tests or demos were rerun for the documentation review.*
