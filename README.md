# Postgres Audit Guard

**Rust security and financial-investigation tooling for PostgreSQL workflows.**

A database operator attempts to elevate a role, export account data or suppress
logging. Which records should an analyst inspect, and can another investigator
check that the captured records and findings have not changed?

The included account-data lab is one synthetic use case. The tool targets
PostgreSQL security investigations across domains.

Postgres Audit Guard reads **PostgreSQL 15+ `jsonlog`** files, emits bounded,
deterministic security signals and preserves exact source bytes in a verifiable
bundle. An SQL-free **Elastic Common Schema (ECS) NDJSON export** fits existing log
pipelines. The application never connects to a database or executes a SQL statement.

The [transfer-investigation module](docs/FINANCIAL-CRIME.md) examines same-currency
collection/outflow and three-account return patterns in authorized extracts. Every
alert exposes its source records, times and integer calculations; reports can be
verified against an external digest and reproduced from the exact input. It is
human-review support, not an automated finding of crime. The synthetic benchmark
deliberately includes a legitimate merchant settlement that triggers an alert.

```sh
cargo run --release --locked -- triage-transfers \
  --input examples/financial-crime/transfers.jsonl --output transfer-report.json
python3 scripts/check_transfers.py transfer-report.json
```

## Preserve the analyst decision

[Versioned analyst cases](docs/ANALYST-CASES.md) bind each human review to the exact
source extract and transfer report. Open, request information, record an
explanation or reopen a case while preserving every previous revision and the
original alert. A separate digest and canonical replay check the stored timeline.
The [scripted merchant example](examples/analyst-cases/) keeps its legitimate
settlement alert visible throughout review; no account action or authority report
is automated. Actor labels are not authenticated identities.

## Try the real local database case

```sh
cargo build --release --locked
cargo test --locked
cargo run --release -- scan --input examples/postgres15-local.jsonl --bundle case-001
# Copy the printed anchor.manifest_sha256 into a separately protected record.
cargo run --release -- verify --bundle case-001 --anchor YOUR_TRUSTED_MANIFEST_SHA256
cargo run --release -- export-ecs --input examples/postgres15-local.jsonl --output alerts.ndjson
python3 scripts/check_lab.py case-001
```

The included records were emitted by a **real local PostgreSQL 15.17 instance**,
using original synthetic banking data. They are not production logs or a real
incident. The [database case outcomes](examples/lab-results.json) distinguish
successful exports from rejected privilege changes. The detector itself **does
not infer transaction success** from logs. Ordinary `log_statement` records are
emitted before execution; duration records are completion logging, but do not
establish transaction commit or authorized intent.

To regenerate everything with your own PostgreSQL installation (15 or newer):

```sh
python3 scripts/run_postgres_lab.py --work-dir /tmp/postgres-audit-new-lab
cargo run --release -- scan --input /tmp/postgres-audit-new-lab/postgres-cases.jsonl --bundle case-002
python3 scripts/check_lab.py case-002
```

The script creates a **new cluster**, listens only on a private Unix socket,
executes six bounded lab cases and stops that cluster. It never connects to an
existing database. Supply `--bindir` if PostgreSQL tools are outside `PATH`.
No server packages or settings are changed by the script. The lab runner is
Unix-only; CI is configured for Rust unit/integration tests on Linux, macOS and Windows.

## Deliver minimized alerts through existing tools

The optional [Filebeat/Elasticsearch handoff](docs/ELASTIC.md) validates an entire
ECS batch before publication. `prepare-elastic` rejects malformed or injected
fields and conflicting same-ID records, and counts equivalent duplicates. The
isolated integration harness checks stored documents and versions through actual
Filebeat ingestion, collector restart and fresh-registry replay. It keeps host
names, log paths, raw SQL and captured identities out of indexed documents.

```sh
cargo run --release --locked -- prepare-elastic \
  --input alerts.ndjson --output validated.ndjson
```

The mutable search index remains separate from sealed source evidence. Stable
IDs are not writer authentication, exactly-once processing or cross-batch
conflict protection. The lab uses original synthetic data and performs no
automatic account action.

## What the code demonstrates

- Bounded streaming ingestion: record, file and count limits enforced before
  growing the reusable input buffer; exact bytes and input ordering preserved.
- Typed, fallible Rust interfaces, explicit failure propagation and no project
  `unsafe` code. Malformed data does not become an empty successful report.
- SQL token-aware detection: comments and string literals cannot become commands.
  This is lexical/structural triage, not complete SQL semantic interpretation.
- Evidence lifecycle: incomplete markers, exclusive output creation, SHA-256
  record chaining, file digests, explicit flush/sync and an external trust anchor.
- Separate original evidence and privacy-minimized ECS exports; no SQL literals,
  usernames or database names in the ECS output.
- Regression, property and corruption tests, plus a real PostgreSQL lab in CI.

## Detection policy

| Rule | Analyst signal |
| --- | --- |
| DB001 | Role capability elevation such as SUPERUSER, CREATEROLE or BYPASSRLS |
| DB002 | Privileged memberships or grants |
| DB003 | Server-side program output through COPY |
| DB004 | Export from configured-in-code synthetic banking-sensitive table names |
| DB005 | Logging suppression changes |
| DB006 | Permission or authentication failures observed in SQLSTATE |
| DB900 | SQL analysis coverage gap, including bounded/unsupported dynamic forms |

Signals are not proof of malicious intent. An authorized maintenance operation can
trigger them. Multiple log records can describe the same attempted action; alert
counts are not incident counts. Table coverage and dynamic-SQL limitations are
documented in [the security model](docs/SECURITY.md).

## Evidence and existing tools

The sealed bundle contains `raw.bin`, `records.jsonl` and `manifest.json`.
Verification requires the expected manifest SHA-256 from a **separate trusted
channel**. A digest stored beside mutable evidence alone cannot establish trust.
This detects changes after collection; it cannot prove the logger's identity,
that every original record was captured, or legal admissibility.

[Architecture and decisions](docs/ARCHITECTURE.md) ·
[Security model](docs/SECURITY.md) ·
[ECS / Elastic integration](docs/ELASTIC.md) ·
[Measured results](docs/RESULTS.md) ·
[Analyst workflow](docs/ANALYST-WORKFLOW.md) ·
[Provenance](PROVENANCE.md)

This is a defensive engineering reference implementation with a bounded transfer
screening module. It is not a production fraud/AML engine, blocking control,
banking certification or court-certified forensic tool.
No association with a bank, law-enforcement agency or software vendor is implied.
