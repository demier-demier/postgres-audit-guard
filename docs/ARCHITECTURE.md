# Architecture and decisions

```text
PostgreSQL jsonlog file (read-only)
             |
bounded byte reader -> serde validation -> PostgreSQL SQL tokens -> rule signals
             |                                      |
             +------ exact source bytes ------------+--> evidence bundle
                                                    +--> optional ECS export
```

## Decisions

The [transfer module](FINANCIAL-CRIME.md) is a separate bounded batch path:
PostgreSQL JSONB export or authorized NDJSON -> strict typed records -> currency/account
indices -> temporal amount patterns -> canonical source-hashed report. It stores
at most 20,000 records from 16 MiB, sorts actual timestamp instants, and limits
candidate work and output references. Monetary sums and ratio products use checked
`u128`; evidence amounts are decimal strings. Report replay requires an external
digest and exact canonical bytes from the current implementation.

1. **Offline ingestion.** No database credential, network listener, server-side
   extension or SQL execution belongs in the scanner. Administrators control log
   collection outside this tool. A separate lab script operates only its new cluster.
2. **Bounded streaming.** One reusable line buffer and one normalized event are
   processed at a time. Default limits: 1 MiB/record, 256 MiB/input and one million
   records. The detector separately caps SQL at 64 KiB, 8,192 tokens and nesting 32.
   Evidence journal lines have their own cap. Unknown PG fields stay in raw bytes.
3. **Ownership and failure.** `BundleWriter` owns its writers and consumes itself
   on finish. Any append error poisons it. Scanner/callback errors propagate before
   finish, leaving an incomplete marker. No recovery silently discards bad input.
4. **Explicit outcomes.** A statement log is evidence of logging an attempt, not
   execution success. An ERROR/FATAL/PANIC record can support `failure_observed`.
   No detector output claims success. Real lab exit codes are separate evidence.
5. **Conservative scope.** The PostgreSQL lexer avoids literal/comment matching
   errors, but rule recognition is structural/lexical. It is not a complete SQL
   analyzer, database authorization engine, anomaly model or automatic response.
6. **Anchored preservation.** Record payloads include exact-byte hashes, source
   offsets and the preceding chain digest. A sealed manifest binds the two files,
   lengths, counts and final chain. The verifier checks a separately supplied
   manifest SHA-256 before trusting it, then checks bytes and normalized consistency.
7. **Privacy separation.** Original evidence stays unredacted in owner-only Unix
   files. ECS exports contain stable source hashes and rule information without
   SQL, message text, usernames or database names. This is field minimization,
   not a general anonymization guarantee. Derived exports are outside the seal.
8. **Small dependency surface.** Standard Rust I/O, serde, SHA-256 and the
   PostgreSQL lexer. No custom cryptographic primitive, custom unsafe code,
   database driver or runtime model dependency. Sequential ingestion keeps source
   order deterministic; measured need would precede adding concurrency.

## Failure contract

- Existing evidence directories and export files are refused.
- Malformed input, limit violations and callback I/O failure return nonzero.
- Partial bundles remain incomplete and cannot verify.
- ECS export uses a temporary file and no-clobber persist after a successful scan.
- Verification rejects changed, reordered, truncated or appended sealed content.
- Empty input is a valid zero-record bundle; it is not evidence of no suspicious activity.
- The external anchor authenticates the selected bytes only relative to trust in
  its acquisition. An attacker who controls both evidence and anchor can replace both.

## Reproduce validation

`cargo test --locked` exercises parser boundaries, fragmented reads, malformed
records, SQL literal/comment controls, property tests, evidence corruption and CLI
failure behavior. CI also generates fresh PostgreSQL logs and checks four positive
scenarios and two benign controls. That six-case corpus is not a precision/recall
measurement or a production readiness claim.

## Evidence-bound analyst snapshots

The [analyst case path](ANALYST-CASES.md) consumes an independently anchored,
canonically replayed transfer report and the same source extract. It binds one
alert by index and full digest, then chains explicit human review events to both
that immutable context and the preceding snapshot. A new file is published for
each revision; past files are preserved. There is no shared mutable head, network
service or automatic response. Canonical decoding, bounded notes/references,
strict UTC instant ordering and an external case digest are checked before append.

This choice keeps offline replay and inspection possible without new runtime
dependencies. It trades centralized concurrency control and authentication for an
explicit requirement to keep trusted current-head anchors in an existing system.
Files are content-synced and persisted without replacement, but parent-directory
sync and crash-atomic head updates are not provided. See the threat model and
precise persistence limits in the case guide.
