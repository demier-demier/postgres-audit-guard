# Observed validation — 2026-10-31

## Financial-investigation extension

The transfer workflow imported **58 original synthetic transactions into PostgreSQL
15.17 JSONB**, exported them through `psql` and verified exact value preservation.
Rust produced four alerts: two TF001 collection/outflow patterns and two TF002
three-account returns. All **12 authored scenarios** matched their expected rule
and source-record sets. One of the four alerts is an intentionally legitimate
merchant settlement; eight other benign controls produced no alert. These are
scenario outcomes, not accuracy estimates on real customers.

The source-bound report passed external-SHA verification and exact canonical
replay. See [captured PostgreSQL output](../examples/financial-crime/observed/postgres-transfers.jsonl),
[analyst report](../examples/financial-crime/observed/report.json),
[scenario evaluation](../examples/financial-crime/observed/evaluation.json) and
[reproduction](FINANCIAL-CRIME.md). Source values remain synthetic even though the
database import/export and Rust analysis are real execution.

Independent review rejected ambiguous JSON reports with duplicate keys, required
canonical byte replay, and corrected fractional-second alert ordering to compare
typed instants. Tests also exercise actual default work/output caps, mixed currencies,
equal timestamps, exact ratio boundaries and monetary sums larger than `u64`.

After this extension, the Mac suite passed **52 library tests + 20 CLI tests = 72
tests**, along with strict Clippy, formatting and Python lint. The original core
also passed Linux/macOS/Windows CI and the PostgreSQL 16 lab at commit `92da31b`;
the initial Windows unused-mut lint failure was corrected explicitly.

## Real PostgreSQL behavior

PostgreSQL 15.17 ran in a fresh cluster on Apple M4 Pro / macOS 27.0.1,
with no TCP listener and a private Unix socket. The lab ignored inherited PG
connection settings, including deliberately invalid host/service/port values.
The cluster was stopped after execution.

| Case | Database result | Detector signal |
| --- | --- | --- |
| `SELECT 1` | Succeeded | None |
| SQL-looking string literal | Succeeded | None |
| Reader tries `ALTER ROLE ... SUPERUSER` | Rejected | DB001; failure record also DB006 |
| Reader exports the synthetic account table | Succeeded | DB004; detector outcome remains unknown |
| Reader tries to disable statement logging | Rejected | DB005; failure record also DB006 |
| Reader tries to delete without permission | Rejected | DB006 |

Nine real source records produced eight rule signals across four positive cases.
Both benign controls had no findings. Ordinary statement and error records can
describe the same attempt, so eight signals do not mean eight incidents. This
six-case corpus does not measure general detection precision or recall.

The scanner sealed and independently verified the exact 3,905 fixture bytes;
the ECS exporter produced eight alerts excluding SQL and identities. Inspect
[scan](../examples/observed/scan.json), [verification](../examples/observed/verify.json),
[case checks](../examples/observed/case-checks.json), and
[ECS output](../examples/observed/alerts.ndjson). Reproduce with the README commands;
the captured fixture is stable, while regenerating PostgreSQL logs changes times
and session identifiers and therefore changes the evidence anchor.

## Rust and failure tests

For the initial core milestone on this Mac: **37 library tests + 8 process-level CLI tests passed**, including
property tests, bounded/fragmented input, malformed and duplicate fields, SQL
literal controls, duration-prefixed records, partial output, no overwrite,
altered/reordered/truncated evidence, wrong external anchors and error-message
confidentiality. `cargo fmt --check` and strict Clippy passed.

Independent implementation review found and corrected sensitive values leaking
through JSON error messages, inherited PostgreSQL connection settings in the lab,
startup cleanup handling, missed duration logs, and an expression `FROM` false
positive. An overlong Unix-socket path initially prevented lab startup; the runner
now rejects it before initialization with a shorter-path instruction.

## Bounded repetition benchmark

These measurements describe the core log-analysis implementation at the initial
publication `2639589`, before transfer screening was added. They are not transfer
analysis throughput or a benchmark of every later revision.

Release build, Apple M4 Pro, macOS 27.0.1; three runs per size. The original nine
synthetic records are repeated exactly. Filesystem caches are warm; this tests
streaming behavior and throughput, not new incidents, large SQL or worst-case work.

| Records | Input bytes | Median records/second | Observed peak RSS range (bytes) |
| ---: | ---: | ---: | ---: |
| 9,000 | 3,905,000 | 735,527 | 2,883,584–2,899,968 |
| 90,000 | 39,050,000 | 755,599 | 2,899,968 |
| 450,000 | 195,250,000 | 749,188 | 2,850,816–2,916,352 |

This table measures **file read + parse + deterministic detection**, without
evidence persistence, network or SIEM. RSS is the macOS `/usr/bin/time -l` value;
it is not total physical footprint or a cross-platform memory guarantee. The
short runs are sensitive to scheduler/cache effects. All raw repetitions, timings
and hashes are in [benchmark.json](../examples/observed/benchmark.json).

A separate complete capture of 90,000 records, including hashing and file sync,
took **0.819 seconds** inside the scanner, with reported peak RSS **3,145,728 bytes**.
This is a single warm-cache observation, not an optimized before/after comparison.

```sh
cargo build --release --locked
python3 scripts/benchmark.py --work-dir /tmp/postgres-audit-benchmark-new
```

## Unvalidated boundaries

No live Elastic/Filebeat deployment, production workload, hostile filesystem
race, performance SLA, complete PostgreSQL semantic coverage, legal admissibility
or fraud-detection accuracy is claimed. Windows/Linux runtime coverage is reported
by the repository's actual CI checks, separately from these Mac observations.
