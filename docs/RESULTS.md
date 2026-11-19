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

## Authenticated Filebeat / Elasticsearch lab (2026-11-13)

The [macOS report](../examples/elastic/result-tls-macos.json) records eight
creates and 25 Filebeat duplicate conflicts across the three replay stages.
All stored sources match the unauthenticated control after equivalent UTC
normalization. Six invalid documents received HTTP 400, seven unauthorized
operations received HTTP 403, and missing credentials and a revoked key
received HTTP 401. TLS verification rejected an unknown CA and a hostname
mismatch. See the [reproduction guide](ELASTIC.md) for the exact scope.

Two initial runs timed out allocating the fixture index on a disk above
Elasticsearch's default percentage watermarks. The successful run used
absolute watermarks on the isolated node and checked available space first.

## Persistent receipts before collection (2026-11-13)

The [captured macOS run](../examples/elastic/result-receipts-macos.json) used
separate CLI processes and a new SQLite journal. It accepted eight original
alerts, classified eight identical replays and preserved one changed-payload
conflict for review. Only the initial eight were materialized for the journal's
Filebeat handoff. The TLS collector stored all eight at version 1. A repeated
batch label returned its original receipt, changed bytes under that label
failed, an invalid batch left no receipt, and an existing spool was preserved.
This result demonstrates bounded local reconciliation with synthetic records.

## Delivery reconciliation and recovery (2026-11-14)

The [macOS report](../examples/elastic/result-delivery-macos.json) uses the
same eight synthetic ECS alerts, Filebeat 8.19.6 and Elasticsearch 8.19.6.
The lab held four accepted alerts back and killed the collector after the
first four were indexed. A separate read-only credential observed four
matches and four explicit absences. The recovery spool contained those four
missing IDs. A new collector created all four with zero duplicate conflicts.
A fresh observation confirmed eight version-1 records. An older observation
could still be read but could no longer generate a retry spool.

A privileged synthetic rewrite of identical content produced one version
mismatch and no recovery rows. The read key could neither create documents
nor read another index. In the cross-index probe, Elasticsearch returned HTTP
200 with eight per-document errors. The collector could not read indexed
documents, and a denied capture left no journal observation. Revoking the
observation key returned HTTP 401. The Python tests also cover v1 migration,
atomic rollback after an incomplete response and content comparison across
distinct JSON types.

Initial lab attempts failed while the harness assumed a single HTTP response
code for denial and used a nonexistent index to probe read scope. The passing
run checks per-document errors and uses an existing synthetic second index.
This test controls the backlog and does not reproduce a lost network
acknowledgement. An observation describes what the index returned at capture
time, with no guarantee of write attribution or exactly-once delivery.
Reproduce with the [delivery lab command](ELASTIC.md#reconcile-delivery-and-recover-missing-alerts).

## Lost bulk acknowledgement (2026-11-15)

The [macOS result](../examples/elastic/result-ack-loss-macos.json) used real
Filebeat and Elasticsearch 8.19.6. A loopback TLS relay passed one synthetic
bulk create upstream. Elasticsearch returned HTTP 200 with item status 201 at
version 1. The relay closed the downstream connection without returning an
HTTP response. The collector reported an output failure.

| Checkpoint | Filebeat on-disk offset | Indexed alerts |
|---|---:|---:|
| Seven acknowledged alerts | 4,831 bytes | 7 |
| Lost reply after the eighth create | 4,831 bytes | 8 |
| Restart with the same file and registry | 5,534 bytes | 8 |
| Next restart with an appended duplicate as a control | 6,216 bytes | 8 |

Before the first restart, the read-only credential found all eight expected
sources at version 1, so manual recovery selected zero rows. On restart,
Filebeat counted one duplicate conflict and zero new creates. The appended
control caused one additional duplicate conflict. Across both restarts all
eight sources and versions remained unchanged. A separate read-only check
compared five raw registry captures, eight stored sources and the SQLite
snapshot digest without importing the lab code.

Initial attempts rejected Filebeat's exact startup license query and the
leading whitespace in its bulk request. The passing harness permits that
startup query and still verifies the complete create target and payload.
This is one ambiguous create on an owned single-node lab. Reproduce with
[`--tls --receipts --delivery --ack-loss`](ELASTIC.md#recover-from-a-lost-bulk-acknowledgement).

## Mixed bulk outcomes (2026-11-16)

In the [macOS run](../examples/elastic/result-mixed-bulk-macos.json), one
real Bulk API request returned HTTP 200 and three item results: a 201
create, a 409 version conflict and a 400 rejection by a lab-only ingest
policy. The 409 was an intentional exact replay. A separate read-only
check confirmed its source and version, along with the new create.

The SQLite journal retained all three item outcomes and both exact capture
digests. Reopening the database and submitting the same capture again
returned the same receipt. The read showed six missing alerts, including
the rejected one. The recovery spool withheld that ID and Filebeat delivered
the five unattempted alerts. A second read confirmed seven records at
version 1 with their original sources. The rejected alert remained absent
and available for human review in the receipt. A separate raw-evidence
check compared the three item rows, the two capture digests and the nine
found results across both read snapshots.

The first local attempt hit an HTTP 401 while the fresh test node was
starting. In the next attempt Elastic's generic fail processor returned
item status 500, so the final probe used an explicit invalid-argument
policy to exercise the intended 400 branch. That outcome concerns
synthetic ingestion policy. This lab does not measure financial detection
accuracy, production throughput or Filebeat's own mixed-bulk response
capture. See the [reproduction steps](ELASTIC.md#record-mixed-bulk-outcomes).

## Reviewed retry of held bulk items (2026-11-19)

The [macOS report](../examples/elastic/result-reviewed-retry-macos.json)
uses the original eight synthetic alerts and real Elasticsearch and Filebeat
8.19.6. A scripted operator recorded a hold, two retry decisions later
invalidated by newer evidence, and a final retry after the lab corrected its
own rejecting ingest policy. The last review bound the failed item's request
and response digests, the original source digest and a new read snapshot.

The held review produced no spool. A newer read invalidated one retry decision;
a newly captured failure invalidated another. The final approved spool
contained exactly one retained alert. Filebeat created that alert with zero
duplicate conflicts, and an independent read confirmed all eight original
sources at version 1. A later read also prevented further export from the
same review. Reopening the database preserved every earlier review and both
failure receipts.

The 22 Python regressions include schema migration, stale observations,
updated bulk results, a later hold, existing-file protection and writer
exclusion while exporting a reviewed spool. A separate read-only checker
recomputed four review-basis hashes from SQLite and raw snapshots, checked
four request/response capture digests and compared all eight final sources.
This checker imports no project modules and was run by the same author.

The review basis includes the captured bulk response, whose timing and index
metadata can differ between executions. Its digest identifies that run's
bytes. Functional cross-platform comparisons must retain the observed
statuses and sources while allowing these evidence-bound digests to differ.
The actor identity is declared, and the decisions in this lab are scripted.
The test demonstrates a technical retry workflow within a trusted local
operator boundary. It provides no actor authentication or wall-clock
freshness check for operator-supplied captures. Reproduce with
[`--review`](ELASTIC.md#review-held-items-before-retry).

## Unvalidated boundaries

No production workload, multi-tenant Elastic deployment, hostile filesystem
race, performance SLA, complete PostgreSQL semantic coverage, legal admissibility
or fraud-detection accuracy is claimed. Windows/Linux runtime coverage is reported
by the repository's actual CI checks, separately from these Mac observations.
