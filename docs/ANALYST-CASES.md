# Evidence-bound analyst cases

A legitimate merchant settlement can match a transfer rule. An analyst needs to
record why it was explained, ask for more information, or reopen the review without
rewriting the original alert. These commands preserve a versioned case timeline
bound to the exact report and source extract. Decisions remain explicit human
assertions. Nothing freezes an account, contacts an authority or labels a person.

## Acceptance contract

- Open a case only from a report that matches its independently retained SHA-256
  and exact deterministic replay of the supplied transfer extract.
- Bind the case to its ID, input digest, report digest, zero-based alert index and
  canonical digest of that entire alert, including its policy evidence.
- Preserve the original alert and every earlier revision. A revision writes a new
  snapshot file; it never updates an old one in place.
- Require an actor token, time, reason and cited source-record IDs for each review.
  References must be unique and belong to the selected alert.
- Verify exact canonical JSON, all event and predecessor-snapshot hashes, strict
  version/time ordering and the separately supplied case digest before accepting
  or extending a timeline. Malformed data fails; it is not a clean/empty review.
- Reopen a previously explained case while retaining its prior explanation.

## Reproduce the synthetic workflow

```sh
cargo build --release --locked
cargo test --locked
# Use a new report path and a new work directory.
target/release/postgres-audit-guard triage-transfers \
  --input examples/financial-crime/transfers.jsonl --output transfer-report.json
python3 scripts/check_analyst_case.py \
  --input examples/financial-crime/transfers.jsonl --report transfer-report.json \
  --work-dir /tmp/analyst-review-new
```

The runner invokes the actual Rust CLI in separate processes. The named merchant
fixture goes through `open → needs_information → closed_explained → open`. A second
synthetic case goes to `escalated_for_review`. Actors, times and reasons are scripted;
the checks do not represent real analyst casework. All four detector alerts remain
in the unchanged report, including the deliberately benign matching settlement.

The PostgreSQL CI job runs this same workflow against a fresh export from its
isolated PostgreSQL 16 JSONB lab. No real banking service is contacted. Captured
Mac results and snapshots are in [the example directory](../examples/analyst-cases/).

## Operate through an existing case-management process

Create a single-paragraph UTF-8 note file using your approved editor. Keep notes
out of shell history and process arguments. Use private operator-controlled paths.

```sh
# REPORT_DIGEST comes from your separate trusted case record.
target/release/postgres-audit-guard open-analyst-case \
  --input transfers.jsonl --report report.json --report-anchor REPORT_DIGEST \
  --case-id internal-review-001 --alert-index 0 \
  --actor analyst-001 --at 2026-11-03T12:01:00Z \
  --reason-file opening-note.txt --evidence-ref merchant-01 \
  --output review-v1.json

# Retain the printed case_sha256 independently before later using it.
target/release/postgres-audit-guard revise-analyst-case \
  --input transfers.jsonl --report report.json --report-anchor REPORT_DIGEST \
  --case review-v1.json --case-anchor CASE_V1_DIGEST \
  --disposition closed-explained \
  --actor analyst-002 --at 2026-11-03T12:02:00Z \
  --reason-file explanation.txt --evidence-ref merchant-01 \
  --output review-v2.json

target/release/postgres-audit-guard verify-analyst-case \
  --input transfers.jsonl --report report.json --report-anchor REPORT_DIGEST \
  --case review-v2.json --case-anchor CASE_V2_DIGEST
```

Substitute evidence references from your selected alert; the sample IDs above are
fictional. `--alert-index` is zero-based and bound to the supplied report digest.
The opening state is always `open`. Revision CLI states use hyphens; JSON states
use underscores. The four states describe the review workflow only:

| State | Meaning |
| --- | --- |
| `open` | An explicit review was opened or reopened. |
| `needs_information` | Further context is needed; no factual conclusion follows. |
| `closed_explained` | The operator records an explanation; the original signal remains. |
| `escalated_for_review` | The operator records a referral for human review; no message is sent. |

## Format, persistence and limits

Snapshots contain a fixed schema and immutable binding fields, plus all revisions.
Each event hash includes a domain tag, the full binding digest and every event
field except its own digest. It also binds the previous event hash and the exact
canonical predecessor-snapshot digest. Canonical JSON is the current Rust
`serde_json::Value` serialization with pretty formatting and a final LF; this is
an implementation-specific byte format, not a claim of RFC 8785 conformance.

RFC3339 times are normalized to UTC and compared as instants. Reviews cannot
precede the selected alert's final event. Later revisions must be strictly later;
equivalent timestamps with different offsets are not later. Actor IDs are
pseudonymous ASCII tokens, not authenticated users. Timestamps are operator
assertions, not independent time attestations. Reasons must contain no control
characters; the CLI strips only trailing CR/LF from the note file.

Limits: 16 MiB per input/report/case, 128 revisions, 2,048 bytes per reason, 64 bytes
per actor/case ID, and 1–1,024 distinct evidence references per revision. Existing
transfer analysis work/output limits still apply. This is a bounded snapshot
workflow, not an unbounded journal or concurrent case-management service.

The CLI writes a temporary file in the destination directory, syncs its contents
and persists without replacing an existing destination. It does not sync the
parent directory. A crash can lose the newly created directory entry or leave a
temporary file/link; old case snapshots are not intentionally modified. Do not
assume a transactional latest-head update or crash-proof storage. The underlying
[tempfile no-clobber contract](https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html#method.persist_noclobber)
does not guarantee atomic persistence on every platform. Unix temporary files are
private by default; on Windows enforce appropriate directory ACLs separately.

## Threat model and non-goals

An attacker who edits a snapshot cannot satisfy a previously trusted digest.
Canonical/schema and chain checks also reject ambiguous JSON and inconsistent
history when the operator accidentally supplies a newly computed digest. These
are integrity checks, not signatures or access control. Someone able to replace
both the complete case and its trusted external anchor can fabricate a timeline.

An old authentic snapshot can still verify against its old anchor. Two operators
can create valid branches from the same predecessor; the tool does not determine
which is latest or prevent concurrent conflicting reviews. Maintain a trusted
current-head registry, authorization, retention and custody in your existing
system. Case IDs are not globally unique or reserved by this offline tool.

A valid reason string may still be wrong. The software does not assess truth,
identity, intent, business purpose, legality or evidentiary admissibility. Notes
and identifiers may be sensitive; they are not redacted or encrypted here.
Only original synthetic examples belong in the public repository. Hostile
filesystem races, malicious administrators, source completeness and authenticated
collection are outside this milestone. No statistical model or AI inference runs.
