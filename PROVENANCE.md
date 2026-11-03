# Provenance

The Rust implementation, lab generator and fixtures are original portfolio work.
No employer/client source code, operational data or system names are used.

- `examples/postgres15-local.jsonl`: actual PostgreSQL 15.17 jsonlog output from
  six scripted local cases, restricted to the case application names. Synthetic
  `bank_accounts` data and `lab_reader` role; no real customers or transactions.
- `examples/lab-results.json`: observed `psql` exit codes and stopped-cluster status.
  These outcomes are independent of the detector's unknown/failure labels.
- `examples/financial-crime/transfers.jsonl` and `expected.json`: 58 hand-authored
  synthetic transfers in 12 labelled scenarios, including a deliberately benign
  matching merchant settlement. Labels are scripted context, not actual crimes.
- `examples/financial-crime/observed/`: actual isolated PostgreSQL 15.17 JSONB
  import/export, Rust report, external-hash replay and scenario-check results.
  No real account identifiers, customers or transaction histories are used.
- `examples/analyst-cases/`: actual Rust CLI snapshots and checks over the same
  original synthetic transactions. Analyst tokens, review times and note contents
  are scripted fixture context, not authenticated staff or real investigations.
  Adjacent digest files are reproduction outputs, not independent trusted storage.
- Rust `sqlparser` supplies PostgreSQL tokenization. Detection policy remains
  original bounded lexical/structural logic, not full SQL semantics.
- Dependencies retain their own licenses through Cargo metadata. The project is MIT.

Technical sources:

1. [PostgreSQL 15 logging documentation](https://www.postgresql.org/docs/15/runtime-config-logging.html),
   especially JSON logging and pre-execution statement logging.
2. [Elastic Common Schema](https://www.elastic.co/docs/reference/ecs/ecs-event)
   for interoperable event fields and explicit outcome values.
3. [INTERPOL digital forensics overview](https://www.interpol.int/How-we-work/Innovation/Digital-forensics)
   as context for preservation and interpretable evidence. The project is not
   affiliated with, used by or endorsed by INTERPOL.

Banking/security career relevance is not an employment, regulatory approval or
operational deployment claim. Rules are deterministic; no model inference is used.
