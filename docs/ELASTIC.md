# Validate and deliver minimized alerts to Elastic

The optional handoff connects the Rust scanner to existing Filebeat/Elasticsearch
software. The scanner and evidence verifier still work entirely offline.
This path exports **PostgreSQL security rule signals**, not transfer reports or
human analyst notes, and does not create native Kibana detection-engine alerts.

## Prepare a bounded export before collection

```sh
cargo build --release --locked
target/release/postgres-audit-guard export-ecs \
  --input examples/postgres15-local.jsonl --output alerts.ndjson
target/release/postgres-audit-guard prepare-elastic \
  --input alerts.ndjson --output validated.ndjson
```

Both commands refuse to replace an existing output. `prepare-elastic` validates
the entire bounded batch before publishing a canonical NDJSON file. It rejects
unknown and duplicate JSON fields, malformed records, unsupported schemas,
invalid field combinations, mismatched identifiers and conflicting documents
with the same identifier. Equivalent repeated documents are counted and emitted
once, preserving first-seen order. A malformed later row leaves no published
partial batch. Limits are 16 MiB per input, 16 KiB per record and 20,000 records.

`event.id` is SHA-256 of `event.hash + ":" + rule.id`; `event.hash` represents exact
captured source bytes. The reported input/output digests are useful for a handoff
receipt, but do not authenticate the producer or seal the export. Two identical
captured records and the same rule share an identifier. Counts are document
counts, not numbers of distinct incidents or people.

The original evidence store remains authoritative for source inspection.
`event.outcome` stays `unknown` unless a failure was observed. Authorized work can
trigger a signal and must remain subject to human review.

## Reproduce the isolated integration

Use trusted **Elasticsearch and Filebeat 8.19.6** archive installations, downloaded
from Elastic and checked against their published SHA-512 checksums. This pinned
version defines the reproducibility target; it is not a recommendation to deploy
that version to production or a claim about the latest available release.
The binaries retain their own upstream licenses and are not redistributed here.

```sh
python3 scripts/run_elastic_lab.py \
  --elasticsearch-home /path/to/elasticsearch-8.19.6 \
  --filebeat-home /path/to/filebeat-8.19.6 \
  --binary target/release/postgres-audit-guard \
  --work-dir /tmp/postgres-audit-elastic-new
```

The harness requires a **new directory** and starts its own single-node service
on loopback, with a new data directory and a basic license. It does not accept an
existing cluster URL. Authentication/TLS are disabled only for this synthetic,
trusted-host lab; the harness configuration is not a production deployment recipe.
No trial, paid service, real customer logs or existing database is used.

The runner exercises the shipped Filebeat configuration, strict index mapping and
ingest pipeline. It checks complete stored documents, stable identifiers, outcome
preservation and observed acknowledgements, duplicate conflicts and document versions. It also checks restart/replay and
rejection behavior. It stops the processes it starts and writes a sanitized
`result.json`; raw logs/configuration stay in the private work directory.

## Boundaries for an existing deployment

The files in [`integrations/elastic`](../integrations/elastic/) are an explicit
starting point, not an auto-installer for an organization's cluster. Review them
under your existing deployment, access and retention controls:

- Filebeat must watch only the validated, immutable publication directory, with
  an operator-owned persistent registry. Keep incomplete/private source files
  outside that directory.
- Copy `event.id` into `@metadata._id` for a stable Elasticsearch document ID.
  Keep the source `event.id` available for inspection. The shipped collector uses
  explicit `create` operations so an existing ID is not replaced.
- Strip Filebeat-added host, agent and log-path metadata. Allowlist only the
  original minimized alert fields before delivery; apply strict sink mappings
  and validation as a second boundary.
- Use your existing TLS, authentication and least-privilege index writer.
  Prefer a `create_doc` writer role and keep administrator setup credentials away
  from the collector. The unauthenticated lab does not validate these permissions.
- Monitor rejected events and output failures. A healthy process or an unchanged
  document count is not evidence that every row was delivered.

The shipped collector uses **create-only writes to one normal index**. Initial
creates succeed; replay attempts with existing IDs receive HTTP 409 and appear in
Filebeat's duplicate counters. The existing document and version are preserved.
This is idempotent stored content, not exactly-once delivery. Count duplicates
separately from fresh successful creates when interpreting acknowledgements.

A 409 proves only that the ID already exists: it does **not** distinguish an exact
replay from a different payload claiming the same source hash/rule. The preflight
rejects conflicting duplicates within one batch, but there is no global conflict
registry. Preserve and investigate conflicting publications in a trusted external
workflow. Source hashes and IDs do not authenticate the producer. Index rollover,
changed rules/versions, multiple sources and concurrent writers need an explicit
policy. Administrators or differently configured writers can still replace/delete
index documents; the index is a searchable derivative, not immutable evidence or
a replacement for externally anchored source bundles.

Timestamps, SQLSTATE and hashes remain linkable. Field minimization is not
anonymization. No case closure, account blocking, accusation or authority report
is automated by this integration. Rules remain deterministic; no model inference
or vendor certification is implied.

## Primary technical references

- [Filebeat 8.19 filestream input](https://www.elastic.co/guide/en/beats/filebeat/8.19/filebeat-input-filestream.html)
- [Filebeat document deduplication](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-deduplication)
- [Elasticsearch output configuration](https://www.elastic.co/guide/en/beats/filebeat/8.19/elasticsearch-output.html)
- [Elasticsearch archive installation](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-from-archive-on-linux-macos)
- [Filebeat metadata fields](https://www.elastic.co/guide/en/beats/filebeat/8.19/add-fields.html)
- [Filebeat writer privileges](https://www.elastic.co/guide/en/beats/filebeat/8.19/privileges-to-publish-events.html)
- [ECS event fields](https://www.elastic.co/docs/reference/ecs/ecs-event)
- [ECS rule fields](https://www.elastic.co/docs/reference/ecs/ecs-rule)
