"""Reproduce a bounded synthetic repetition benchmark; not a detection-quality dataset."""

import argparse
import hashlib
import json
import platform
from pathlib import Path
import re
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument(
        "--binary", type=Path, default=Path("target/release/postgres-audit-guard")
    )
    args = parser.parse_args()
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    fixture = Path("examples/postgres15-local.jsonl").read_bytes()
    binary = args.binary.resolve()
    result = {
        "schema": "postgres-audit-repeated-fixture-benchmark/v1",
        "fixture_sha256": hashlib.sha256(fixture).hexdigest(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "system": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "scope": "File read, JSON parse and deterministic detection only. No persistence, network or SIEM. Repeated synthetic fixture; warm filesystem cache; no quality estimate.",
        "cases": [],
    }
    for repeat in [1000, 10000, 50000]:
        path = args.work_dir / f"repeated-{repeat}.jsonl"
        with path.open("wb") as f:
            for _ in range(repeat):
                f.write(fixture)
        runs = []
        for _ in range(3):
            command = [str(binary), "bench", "--input", str(path)]
            if platform.system() == "Darwin":
                command = ["/usr/bin/time", "-l"] + command
            process = subprocess.run(
                command, capture_output=True, text=True, check=True, timeout=120
            )
            measured = json.loads(process.stdout)
            # macOS time -l reports RSS in bytes. Do not reinterpret it as physical footprint.
            match = re.search(r"(\d+)\s+maximum resident set size", process.stderr)
            if match and platform.system() == "Darwin":
                measured["max_rss_bytes"] = int(match[1])
            runs.append(measured)
        result["cases"].append(
            {
                "fixture_repetitions": repeat,
                "records": len(fixture.splitlines()) * repeat,
                "input_bytes": path.stat().st_size,
                "median_records_per_second": statistics.median(
                    x["records_per_second"] for x in runs
                ),
                "runs": runs,
            }
        )
    output = args.work_dir / "benchmark.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
