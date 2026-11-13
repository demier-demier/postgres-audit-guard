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

## Reproduce the authenticated mode

Add `--tls` to the same command and choose a different, empty destination path
that does not exist yet. This mode uses OpenSSL, a fresh local CA and a certificate
for `127.0.0.1`. It verifies TLS against that CA and hostname in both the
harness and Filebeat. TLS is also enabled on the node transport listener.

The harness provisions the index and final ingest pipeline with an ephemeral
bootstrap credential. Filebeat receives only a separate API key, valid for up
to 30 minutes, with cluster `monitor` and `create_doc` on the exact pre-created
index. The harness writes secrets to the vendor keystores via stdin and revokes
the key after the probes. These files, the node TLS private key and raw logs
belong in the private run directory. Never publish that directory.

The [captured macOS result](../examples/elastic/result-tls-macos.json) records
eight creates, eight conflicts after a registry restart and append, 16 conflicts
on a fresh registry replay, and one conflict for different content claiming an
existing ID. All eight documents stayed at version 1 with identical normalized
content. The six invalid document probes returned HTTP 400, with a receipt
containing the case name, document ID, canonical body SHA-256 and response error
type. These receipts cover deliberate lab probes. They do not implement a
production dead-letter queue or capture every possible Filebeat rejection.

Seven permission probes returned HTTP 403 with the collector key: overwrite,
update, document delete, document read, index delete, create in a different
index, and ingest pipeline administration. A request without credentials and
a request after key revocation returned HTTP 401. The TLS client rejected an
untrusted CA and a hostname mismatch. The result excludes credentials and
raw Elasticsearch errors. The lab needs more than 2 GiB free and sets absolute
disk watermarks for its owned instance so the small synthetic fixture works
on large disks with a high percentage of space already in use.

## Classify repeated IDs before Filebeat

The optional receipt journal uses Python's SQLite module and calls the same
Rust validator before starting a transaction. Start a journal in a private
local directory. Use a separate journal for each index and policy boundary.

```sh
python3 scripts/elastic_receipts.py --journal receipts.db init
python3 scripts/elastic_receipts.py --journal receipts.db submit \
  --batch initial --binary target/release/postgres-audit-guard --input alerts.ndjson
python3 scripts/elastic_receipts.py --journal receipts.db receipt --batch initial
python3 scripts/elastic_receipts.py --journal receipts.db materialize \
  --batch initial --output ready.ndjson
```

The first validated canonical payload for an ID is accepted. A later byte-equal
canonical payload is a replay. A different payload for that ID is retained
privately with its hash and the first accepted batch for human review. Repeating
a batch label with identical input bytes returns its prior receipt. Reusing the
label for different bytes fails. A malformed batch creates no receipt.
`submit` exits 0 for accepted or replay-only batches, 2 if it records conflicts,
and 1 on an error. In a mixed batch, new IDs remain accepted even when the
command exits 2. Review the receipt before publishing accepted rows.

Use `export-conflicts --batch LABEL --output PATH` to recover rejected canonical
payloads into a new private file outside Filebeat's watch directory.
`materialize` emits only records first accepted in that batch. After an
interruption between commit and publication, materialize the original batch
again. It writes a temporary file and links the final name on the same local
filesystem, refusing an existing output. Configure Filebeat to match completed
NDJSON files and exclude the temporary suffix. Monitor Filebeat and Elasticsearch
separately for delivery acknowledgements.

The journal caps each input at 16 MiB, limits journals to 2,000 batches and
sets a 128 MiB SQLite page cap. Temporary files and rollback journal space
are additional. At capacity a write fails without evicting history.
Rotating the journal starts a new deduplication boundary. Changes in timestamp
representation can count as conflicts because equality uses canonical bytes.
Keep raw source exports separately and use pseudonymous batch labels. A local
writer who can replace the journal can alter history. A trusted operator owns
the binary, local paths and spool. SQLite cannot commit Filebeat delivery in
the same transaction.

Add `--tls --receipts` to the lab command to materialize accepted records before
Filebeat starts and check persistence across separate CLI processes. Existing
direct sink replay and privilege probes run as controls.

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
  from the collector. The authenticated lab validates the exact role and index
  above. It does not establish what privileges a different Filebeat configuration needs.
- Monitor rejected events and output failures. A healthy process or an unchanged
  document count is not evidence that every row was delivered.

The shipped collector uses **create-only writes to one normal index**. Initial
creates succeed; replay attempts with existing IDs receive HTTP 409 and appear in
Filebeat's duplicate counters. The existing document and version are preserved.
This is idempotent stored content, not exactly-once delivery. Count duplicates
separately from fresh successful creates when interpreting acknowledgements.

A 409 proves only that the ID already exists: it does **not** distinguish an exact
replay from a different payload claiming the same source hash/rule. The preflight
rejects conflicting duplicates within one batch. The receipt journal can classify
conflicts across its own batches. It has no visibility into other writers or
journals. Source hashes and IDs do not authenticate the producer. Index rollover,
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
- [Elasticsearch create_doc privilege](https://www.elastic.co/docs/reference/elasticsearch/security-privileges)
- [Filebeat API key authentication](https://www.elastic.co/docs/reference/beats/filebeat/beats-api-keys)
- [ECS event fields](https://www.elastic.co/docs/reference/ecs/ecs-event)
- [ECS rule fields](https://www.elastic.co/docs/reference/ecs/ecs-rule)
