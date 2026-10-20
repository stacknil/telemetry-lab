"""Execute pinned saved-evidence producer commands and the real consumer twice."""
from __future__ import annotations

import argparse
from hashlib import sha256
from importlib.metadata import version
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import sys
import tarfile

from jsonschema import Draft202012Validator, FormatChecker
from PIL import Image
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from telemetry_lab.io import load_alert_table, load_config, load_feature_table  # noqa: E402

PIN = "1d31d4287036cf2bbd3aeb8059d7d332bedef598"
PROJECT = "projects/linux-process-observe"
DIGEST = "1977b98518497c9a07da6393499cb49e6d0be9140ac5bcd708c2a1cd31a3ad51"
EXPECTED = dict(event_count=7, error_count=0, error_rate=0.0, unique_sources=4,
                unique_targets=7, high_severity_count=0, login_fail_count=0,
                login_success_count=0, config_change_count=0, malware_alert_count=0,
                policy_denied_count=0)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(args, *, cwd, env=None):
    result = subprocess.run([str(arg) for arg in args], cwd=cwd, env=env,
                            capture_output=True, timeout=120)
    if result.returncode:
        raise ValueError("Command failed: " + result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def export_producer(repository, destination):
    # Read immutable Git objects, never execute or overwrite the caller's checkout.
    actual = command(["git", "rev-parse", PIN + "^{commit}"], cwd=repository).decode().strip()
    require(actual == PIN, "Pinned producer commit is unavailable")
    data = command(["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf", "archive", "--format=tar", PIN, PROJECT], cwd=repository)
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts and "\\" not in member.name and ":" not in member.name,
                    "Unsafe producer archive path")
            # git archive includes the requested project's ancestor directory.
            if member.isdir() and path.parts == ("projects",):
                continue
            require(path.parts[:2] == ("projects", "linux-process-observe"), "Unexpected producer archive scope")
            if member.isdir():
                continue
            require(member.isfile(), "Producer archive must contain regular files")
            output = destination.joinpath(*path.parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source:
                output.write_bytes(source.read())
    return destination / PROJECT


def check_result(output, input_path, config_path):
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    manifest = json.loads((output / "run_manifest.json").read_text(encoding="utf-8"))
    for value, schema in ((summary, "telemetry_summary.schema.json"), (manifest, "run_manifest.v2.schema.json")):
        contract = json.loads((ROOT / "schemas" / schema).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(contract)
        Draft202012Validator(contract, format_checker=FormatChecker()).validate(value)
    counts = {key: summary[key] for key in ("normalized_event_count", "window_count", "feature_row_count", "alert_count")}
    require(counts == dict(normalized_event_count=7, window_count=1, feature_row_count=1, alert_count=0), "Unexpected summary counts")
    features = load_feature_table(output / "features.csv")
    require(set(features.columns) == {"window_start", "window_end", *EXPECTED}, "Unexpected feature columns")
    require(len(features) == 1 and features.iloc[0][list(EXPECTED)].to_dict() == EXPECTED, "Unexpected aggregate features")
    row = features.iloc[0]
    require(row.window_start.isoformat() == "2026-07-05T00:05:00+00:00" and row.window_end.isoformat() == "2026-07-05T00:06:00+00:00", "Unexpected observation window")
    require(load_alert_table(output / "alerts.csv").empty, "Default rules unexpectedly alerted")
    require(manifest["artifact_schema_versions"] == {"run_manifest": "run-manifest/v2", "telemetry_summary": "telemetry-summary/v1"}, "Unexpected artifact versions")
    for kind, path in (("input", input_path), ("config", config_path)):
        require(manifest[kind + "_file_digests"] == {f"external/{kind}/{path.name}": "sha256:" + sha256(path.read_bytes()).hexdigest()}, "Incorrect exact-byte fingerprint")
        normalized = path.read_text(encoding="utf-8").encode("utf-8")
        legacy = sha256(path.name.encode() + b"\0" + normalized + b"\0").hexdigest()
        require(manifest[kind + "_digest"] == "sha256:" + legacy, "Incorrect legacy digest")
    names = {Path(name).name for name in summary["generated_artifacts"]}
    expected_names = {"features.csv", "alerts.csv", "summary.json", "run_manifest.json",
                      "event_count_timeline.png", "error_rate_timeline.png", "alerts_timeline.png"}
    require(names == {path.name for path in output.iterdir()} == expected_names, "Missing or unexpected output artifact")
    for name in names:
        if name.endswith(".png"):
            with Image.open(output / name) as image:
                require(image.format == "PNG" and min(image.size) > 0, "Invalid plot")
                image.verify()
    return summary, manifest


def reproduce(repository, output):
    repository, output = repository.resolve(), output.resolve()
    require(not output.is_relative_to(ROOT) and not output.is_relative_to(repository), "Outputs must be outside both repositories")
    output.mkdir(parents=True, exist_ok=False)  # refuse collisions; never remove existing outputs
    producer = export_producer(repository, output / "pinned-source")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1", MPLBACKEND="Agg",
               MPLCONFIGDIR=str(output / "plot-config"))
    receipts = []
    def execute(module, args, source):
        invocation = [sys.executable, "-m", module, *map(str, args)]
        stdout = command(invocation, cwd=output, env=dict(env, PYTHONPATH=str(source / "src")))
        receipts.append({"argv": invocation, "exit_code": 0, "stdout": stdout.decode("utf-8", errors="replace")})
    for name, instant in (("baseline", "2026-07-05T00:00:00Z"), ("changed", "2026-07-05T00:05:00Z")):
        fixture = producer / "tests/fixtures" / name
        execute("linux_process_observe", ["snapshot", "--proc-root", fixture / "proc", "--ss", fixture / "ss.txt",
            "--host-id", "lab-host", "--observed-at", instant, "--output-dir", output / name], producer)
    execute("linux_process_observe", ["diff", "--before-processes", output / "baseline/process_snapshot.json",
        "--after-processes", output / "changed/process_snapshot.json", "--before-links", output / "baseline/process_socket_links.json",
        "--after-links", output / "changed/process_socket_links.json", "--output-dir", output / "diff"], producer)
    input_path = output / "diff/telemetry_events.jsonl"
    execute("linux_process_observe", ["adapt", "--input", output / "diff/process_diff.json", "--output", input_path], producer)
    producer_hashes = {}
    for folder, names in (("baseline", ("process_snapshot.json", "process_socket_links.json")),
                          ("changed", ("process_snapshot.json", "process_socket_links.json")),
                          ("diff", ("process_diff.json", "report.md", "telemetry_events.jsonl"))):
        for name in names:
            data = (output / folder / name).read_bytes()
            golden = (producer / "tests/golden" / folder / name).read_bytes()
            # Compare structured contracts; only the JSONL contract is byte-exact.
            if name.endswith(".json"):
                equal = json.loads(data) == json.loads(golden)
            elif name.endswith(".md"):
                equal = data.decode().replace("\r\n", "\n") == golden.decode().replace("\r\n", "\n")
            else:
                equal = data == golden
            require(equal, "Producer output differs from pinned golden: " + folder + "/" + name)
            producer_hashes[folder + "/" + name] = sha256(data).hexdigest()
    require(producer_hashes["diff/telemetry_events.jsonl"] == DIGEST, "Producer JSONL digest changed")
    generated = [json.loads(line) for line in input_path.read_text(encoding="utf-8").splitlines()]
    canonical = [json.loads(line) for line in (ROOT / "tests/fixtures/process_evidence/telemetry_events.jsonl").read_text(encoding="utf-8").splitlines()]
    require(generated == canonical, "Generated producer records differ semantically from the consumer fixture")
    results = []
    for name in ("one", "two"):
        directory = output / name
        directory.mkdir()
        config = load_config(ROOT / "configs/default.yaml")
        config.update(input_path=str(input_path), output_dir=str(directory / "artifacts"))
        path = directory / "integration.yaml"
        path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8", newline="\n")
        execute("telemetry_lab.cli", ["run", "window", "--config", path], ROOT)
        results.append(check_result(directory / "artifacts", input_path, path))
    for name in ("features.csv", "alerts.csv"):
        require((output / "one/artifacts" / name).read_bytes() == (output / "two/artifacts" / name).read_bytes(), "Structured output is unstable")
    stable_summary = ("normalized_event_count", "window_count", "feature_row_count", "alert_count", "triggered_rule_names", "triggered_rule_counts", "cooldown_seconds")
    require({key: results[0][0][key] for key in stable_summary} == {key: results[1][0][key] for key in stable_summary}, "Summary metrics are unstable")
    for key in ("tool_version", "demo_id", "input_digest", "input_file_digests", "artifact_schema_versions", "execution_mode"):
        require(results[0][1][key] == results[1][1][key], "Manifest input contract is unstable")
    report = dict(producer_commit=PIN, consumer_base="de542cb3cadba776c8e759f786152f9222fdfdb7",
        python=platform.python_version(), platform=platform.system(),
        packages={name: version(name) for name in ("telemetry-lab", "pandas", "matplotlib", "PyYAML", "jsonschema")},
        commands=receipts, producer_output_sha256=producer_hashes, schema_validations=4,
        producer_comparison="five JSON objects; report text with normalized newlines; JSONL exact bytes and parsed records",
        structured_outputs="stable; output paths/config fingerprints differ by design", png="six decoded PNG smoke checks; no cross-platform byte claim")
    (output / "integration_receipt.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("PASS: four producer commands, seven golden contracts, two consumer runs, four schema validations")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", type=Path, required=True, help="local systems-foundations Git repository containing the exact pin")
    parser.add_argument("--output-root", type=Path, required=True, help="new disposable directory outside both repositories")
    args = parser.parse_args(argv)
    try:
        reproduce(args.producer, args.output_root)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"FAIL: {error}\n")


if __name__ == "__main__":
    main()
