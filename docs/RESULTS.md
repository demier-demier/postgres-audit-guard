# Observed validation

## Analyst review snapshots — 2026-11-03

A fresh socket-only PostgreSQL 15.17 lab round-tripped the same **58 synthetic
transfers**, preserving every value and stopping its cluster afterward. The
canonical Rust report reproduced the prior four alerts across 12 authored
scenarios, including the intentionally legitimate matching merchant settlement.

The new CLI then persisted and verified **six case snapshots** in separate
processes: merchant open → needs information → explained → reopened, and a separate
open → referral-for-review case. Every earlier snapshot, source extract and original
report remained unchanged. States and notes were scripted test context, not real
analyst work. No account blocking, external reporting or crime classification ran.

The Mac validation passed **63 library tests + 31 CLI tests = 94 tests**, including
**22 new case tests**. New coverage includes wrong external anchors, duplicate/
unknown JSON fields, rehashed structural tampering, cross-alert references,
subsecond/offset timestamp ordering, private-note diagnostics, revision budgets,
no-overwrite failures, valid historical snapshots and explicit branch behavior.
Unix-specific tests also checked file modes and symlink rejection. Formatting,
strict all-target Clippy and the release build passed.

A fresh `core.autocrlf=true` checkout exposed a reproducibility failure: Git
converted captured JSON to CRLF, changing its anchored bytes. Explicit LF
attributes now preserve JSON/NDJSON evidence. The new exact-byte CLI regression
verifies all six published snapshots against their recorded digests, and the
controlled checkout successfully replayed the captured cases after the fix.

Inspect [the snapshots and measured results](../examples/analyst-cases/) or
[reproduce the workflow](ANALYST-CASES.md). These tests establish the bounded
implementation's observed behavior, not authenticated analyst identities, latest-head
consensus, real-world fraud accuracy, crash-proof storage or production readiness.
Remote platform results are reported by the actual CI run separately.

## Financial-investigation extension — 2026-10-31

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

## Actual Filebeat / Elasticsearch integration (2026-11-04)

The optional integration ran on this Apple Silicon Mac with vendor-checksummed
Elasticsearch and Filebeat **8.19.6**, basic license, a new loopback-only node and
the existing nine-record synthetic PostgreSQL fixture. See the complete
[result](../examples/elastic/result-macos.json),
[archive provenance](../examples/elastic/vendor-artifacts-macos.json) and
[reproduction instructions](ELASTIC.md). No existing server or customer data was used.

The Rust validator published eight canonical documents. Global Filebeat
allowlisting removed host/agent/path metadata; comparison checked every indexed
source field, normalizing only equivalent timestamp UTC representations without
truncating fractional seconds. Five `failure` and three `unknown` outcomes were
preserved. These are deterministic rule signals for human review, not eight
incidents or findings of criminal conduct.

| Actual Filebeat stage | New creates acknowledged | Duplicate conflicts observed | Stored documents | Version of each document |
| --- | ---: | ---: | ---: | ---: |
| Initial ingest | 8 | 0 | 8 | 1 |
| Restart with persistent registry; append eight repeated rows | 0 | 8 | 8 | 1 |
| Fresh registry replays all sixteen rows | 0 | 16 | 8 | 1 |
| Fresh registry sends one independently prepared, changed same-ID payload | 0 | 1 | 8 | 1 |

The collector explicitly uses `create` operations. Replay proof comes from real
Filebeat duplicate counters and unchanged exact source documents, not merely a
stable total count. The fourth stage demonstrates a limit: a conflicting payload
is also classified as a duplicate. Original content survives, but HTTP 409 alone
cannot tell identical replay from changed content; trusted conflict review remains
outside this implementation. A privileged direct writer can still alter the index.

Six malformed/injected export cases were rejected without publishing a partial
batch. Six invalid direct sink writes returned HTTP 400 and left stored documents
unchanged. A separate direct same-ID create returned HTTP 409. All owned processes
were stopped and the selected HTTP, transport and monitoring ports were confirmed
closed after cleanup. This is a bounded functional run, not a delivery performance,
production access-control or general accuracy benchmark.

Observed failures fixed during real integration:

- License information briefly returned 404 during node initialization; startup
  now waits within a fixed budget after checking its own cluster identity.
- Explicitly retaining `@timestamp` with Filebeat's include-fields processor
  duplicated the serialized field. The config now relies on intrinsic retention.
- Input-level processors ran before Filebeat added host/agent metadata. Strict
  sink mappings rejected these documents; moving the allowlist to global
  processors removed those fields before delivery.
- Filebeat create operations report HTTP 409 through duplicate counters rather
  than overwrite/version increments. The harness now measures that real behavior
  and explicitly tests changed-content conflicts.

Final local checks: **66 Rust library tests + 38 CLI tests = 104 passed**, plus
**four Python harness safety regressions** (redirect refusal, shutdown race,
all-process cleanup after an error and nanosecond comparison). Formatting,
all-target strict Clippy, release build and Python compilation passed. Independent
review checked the controls and observed run. CI reruns Rust on Linux/macOS/Windows,
a fresh PostgreSQL lab and the actual Elastic integration on Linux; consult the
corresponding workflow result for remote status.

## Unvalidated boundaries

No production workload, authenticated/TLS Elastic deployment, hostile filesystem
race, performance SLA, complete PostgreSQL semantic coverage, legal admissibility
or fraud-detection accuracy is claimed. Windows/Linux runtime coverage is reported
by the repository's actual CI checks, separately from these Mac observations.
