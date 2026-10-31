# Provenance

The Rust implementation, lab generator and fixtures are original portfolio work.
No employer/client source code, operational data or system names are used.

- `examples/postgres15-local.jsonl`: actual PostgreSQL 15.17 jsonlog output from
  six scripted local cases, restricted to the case application names. Synthetic
  `bank_accounts` data and `lab_reader` role; no real customers or transactions.
- `examples/lab-results.json`: observed `psql` exit codes and stopped-cluster status.
  These outcomes are independent of the detector's unknown/failure labels.
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
