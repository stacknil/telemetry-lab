# Executable process-evidence integration

This suite checks a saved-evidence producer against the real telemetry consumer.
It adds executable regression evidence after the [19 October case study](case-study-process-evidence-to-telemetry.md);
it does not rerun or replace that historical experiment's private receipts.

## Versions and fixture

- Producer: [systems-foundations at `1d31d4287036cf2bbd3aeb8059d7d332bedef598`](https://github.com/stacknil/systems-foundations/tree/1d31d4287036cf2bbd3aeb8059d7d332bedef598),
  `projects/linux-process-observe`.
- Consumer: this suite is based on `de542cb3cadba776c8e759f786152f9222fdfdb7`.
  Reproduce from the reviewed integration revision containing this guide.
  The historical case used `98ae3ffd1edb47d90eb42b3a8625be830582997e`.
- Offline input: [`tests/fixtures/process_evidence/telemetry_events.jsonl`](../tests/fixtures/process_evidence/telemetry_events.jsonl),
  an unmodified, public synthetic producer golden, with [provenance](../tests/fixtures/process_evidence/provenance.json).
  It is 4,108 LF bytes, SHA-256
  `1977b98518497c9a07da6393499cb49e6d0be9140ac5bcd708c2a1cd31a3ad51`.
  Its scoped `.gitattributes` entry prevents checkout newline conversion.

## Layer A: offline regression gate

Install this checkout's development dependencies in a separate Python 3.11+
virtual environment, then run:

```sh
python -m pip install -e ".[dev]"
python -m pip check
python -m pytest tests/test_process_evidence_integration.py -v
```

The tests execute the actual loader, normalization, windows, features, rules and
CLI. They never fetch the producer, access private receipts or mock the consumer.
The existing ordinary `pytest` CI job includes this layer without extra network
access during test execution.

## Layer B: actual producer commands and two consumer runs

Git and the same environment's development dependencies are required. Obtain
the pinned public producer before running the workflow. From the consumer root:

```sh
git clone https://github.com/stacknil/systems-foundations.git ../process-evidence-producer
git -C ../process-evidence-producer checkout --detach 1d31d4287036cf2bbd3aeb8059d7d332bedef598
python scripts/reproduce_process_evidence.py --producer ../process-evidence-producer --output-root ../process-evidence-run
```

Use a **new** output directory outside both repositories on every invocation.
The runner refuses collisions and performs no cleanup. It reads immutable Git
objects, exports only the pinned project with Git newline conversion disabled,
and executes the exported source. Dirty files in the supplied producer checkout
cannot select the executed source. The producer uses only the standard library;
its exported `src` is selected explicitly for each subprocess. No producer fetch,
package download, live procfs read or network operation occurs inside the runner.

The executable sequence is the following, with `PROJECT` referring to the
exported pinned project and `OUT` to the fresh output directory:

```sh
python -m linux_process_observe snapshot --proc-root "$PROJECT/tests/fixtures/baseline/proc" --ss "$PROJECT/tests/fixtures/baseline/ss.txt" --host-id lab-host --observed-at 2026-07-05T00:00:00Z --output-dir "$OUT/baseline"
python -m linux_process_observe snapshot --proc-root "$PROJECT/tests/fixtures/changed/proc" --ss "$PROJECT/tests/fixtures/changed/ss.txt" --host-id lab-host --observed-at 2026-07-05T00:05:00Z --output-dir "$OUT/changed"
python -m linux_process_observe diff --before-processes "$OUT/baseline/process_snapshot.json" --after-processes "$OUT/changed/process_snapshot.json" --before-links "$OUT/baseline/process_socket_links.json" --after-links "$OUT/changed/process_socket_links.json" --output-dir "$OUT/diff"
python -m linux_process_observe adapt --input "$OUT/diff/process_diff.json" --output "$OUT/diff/telemetry_events.jsonl"
python -m telemetry_lab.cli run window --config "$OUT/one/integration.yaml"
python -m telemetry_lab.cli run window --config "$OUT/two/integration.yaml"
```

The runner supplies each module's source path and starts commands from the
disposable directory. Each consumer config is a fresh copy of `configs/default.yaml`
with only `input_path` and `output_dir` changed. `integration_receipt.json` records
actual argv, exit codes, versions and comparisons. Keep generated artifacts outside
Git; paths in local receipts may reveal local directory names.

## Expected results and boundaries

| Check | Expected contract |
| --- | --- |
| Producer | Four successful commands; five JSON objects and report text match pinned golden content; JSONL matches exact bytes and parsed fixture records |
| Loading and normalization | Seven rows; five required fields; source, target and nested metadata retained |
| Time | All rows at `2026-07-05T00:05:00Z`; one half-open `[00:05:00Z, 00:06:00Z)` window |
| Features | Eleven numeric fields; seven events, four sources, seven targets; error, severity and five configured category counts all zero |
| Rules | Zero alerts with unchanged default rules, thresholds and cooldown |
| Outputs | Seven artifacts per consumer run; both summary/v1 and manifest/v2 pass their schemas with format checks |
| Repetition | Feature/alert CSV bytes and selected summary/manifest fields stable; config fingerprints legitimately differ because output paths differ |
| Plots | Three PNGs per run decode with nonzero dimensions; no cross-platform byte equality claim |

`metadata.time_semantics = snapshot_diff_observed_at` describes comparison
observation time. Window membership uses `timestamp`; the consumer does not
infer occurrence time or validate this advisory marker. `source` has the producer
form `host_id:pid:start_time_ticks`, bounded to same-boot evidence without a boot
identifier. Preservation proves neither cross-reboot identity nor authentication.
Executable and endpoint targets remain context, not independent attribution.

Negative and metamorphic controls cover missing required columns/values,
malformed JSONL and timestamps, changed comparison time, equivalent UTC offsets,
unknown categories, status changes across the existing error threshold, missing
or altered advisory metadata, duplicate timestamps, row ordering, half-open
boundaries and changed raw-byte fingerprints. Unknown categories and numeric
identifiers remain accepted where existing normalization supports them. Metadata
changes can leave aggregation unchanged; duplicate records are counted again.

Per-file manifest fingerprints identify exact input/config bytes. Legacy aggregate
digests separately include labels and normalized text. LF/CRLF changes therefore
change the exact-byte fingerprint while preserving the legacy digest and features.
These values provide content identification, not authenticated provenance.

## Architecture and limitations

Layer B stays an explicit standalone workflow. Adding a second repository checkout
to required PR CI would introduce a network dependency without improving the
offline consumer gate; using mutable producer `main` would weaken reproducibility.
The ordinary CI and all release/publication workflows remain unchanged.

No consumer admission policy, default detection rule, schema, golden demo output
or producer implementation changes. This suite checks structural and bounded
semantic compatibility and reproducibility, not detection efficacy or production
readiness. It adds no collector, new demo, security attribution or private evidence.
Dependency versions are reported rather than locked; other supported environments
must run these checks rather than infer equivalent PNG bytes or performance.
