# Transfer-pattern investigation

The transfer module adds a second input surface alongside PostgreSQL security logs:
an authorized NDJSON transaction extract. It examines patterns for **human review**,
without labelling a person a criminal, freezing an account, submitting a report to
an authority or inferring intent. Rules are deterministic; no trained model is used.

## Investigative questions

- **TF001 — collection and rapid outflow:** did at least three distinct senders
  transfer into an account, followed by outflows of at least 80% of those incoming
  amounts within a 60-minute window, in the same currency?
- **TF002 — three-account return:** did A transfer to B, then B to C, then C to A,
  with three distinct accounts, strictly ordered times, a total duration of at
  most 60 minutes and each onward amount between 80% and 100% of its predecessor?

These thresholds are **original laboratory policy choices**. They are not statutory
reporting limits, recommended bank calibration or regulator-approved detection.
Amounts use integer minor units; currencies are never combined or converted.
Sorting an extract does not establish causality when timestamps are equal.

Rapid onward transfers and connected account activity are investigative context
discussed in the [FCA's review of money-mule detection](https://www.fca.org.uk/publications/multi-firm-reviews/firms-use-national-fraud-database-money-mule-account-detection-tools).
Risk assessment and case context matter; see the [FATF banking risk-based approach](https://www.fatf-gafi.org/content/dam/fatf-gafi/guidance/Risk-Based-Approach-Banking-Sector.pdf.coredownload.pdf).
Neither publication supplies or endorses this implementation or its numerical rules.

## Reproduce the controlled PostgreSQL integration

```sh
cargo build --release --locked
python3 scripts/run_postgres_lab.py --work-dir /tmp/transfer-investigation-new \
  --transfers examples/financial-crime/transfers.jsonl
target/release/postgres-audit-guard triage-transfers \
  --input /tmp/transfer-investigation-new/postgres-transfers.jsonl \
  --output transfer-report.json
# Store the printed report_sha256 in a separately trusted case record.
target/release/postgres-audit-guard verify-transfer-report \
  --input /tmp/transfer-investigation-new/postgres-transfers.jsonl \
  --report transfer-report.json --anchor YOUR_TRUSTED_REPORT_SHA256
python3 scripts/check_transfers.py transfer-report.json
```

The lab creates its own private socket-only PostgreSQL cluster. It imports synthetic
transfer objects into JSONB through CSV-escaped COPY data, exports NDJSON through a
read-only SELECT, verifies all source values survived, and stops its own cluster.
The Rust analyzer never connects to the database. For an existing deployment,
collection, permissions, schema mapping and approval remain with its administrator.

The report includes original record IDs, account links, time ranges, calculations,
policy parameters and input SHA-256. Publication is atomic and refuses replacement.
Verification checks an independently retained digest, then repeats analysis against
the exact source bytes and requires byte-for-byte canonical output from the same
analysis implementation. Formatting changes, duplicate keys and policy changes
therefore fail verification. This establishes integrity and reproducibility, **not source
authenticity, complete account history, unlawful intent or legal admissibility**.

## Data and failure boundaries

Input is capped at 16 MiB and 20,000 records. Duplicate IDs, unknown fields, invalid
timestamps, malformed currency/identifier values, zero or out-of-range amounts and
resource-budget exhaustion are errors, not silently discarded rows. The module
also bounds computational work and evidence output. This is a bounded batch tool,
not an unbounded streaming AML engine. Cross-window history is not retained.

The input must represent committed, unreversed transfers selected by the operator;
there is no reversal, settlement, chargeback or opening-balance model. An account
identifier is not a person, shared ownership or provenance of the money. Three-letter
currency syntax is validated but ISO currency membership is not looked up. No FX,
KYC, device, beneficiary ownership, sanctions or behavioral baseline is inferred.

Reports retain transaction and account identifiers. Protect them as evidence; do
not upload real customer extracts or derived reports to public repositories.
Read-only file checks assume operator-controlled paths, not an adversarial filesystem.

## Deliberately preserved false positive

The [synthetic fixture](../examples/financial-crime/) includes an authorized merchant
settlement that matches TF001. Business context exists only in the scenario label;
the six transaction fields cannot establish it. The report must retain this alert
for analyst review. Suppressing it merely because the test calls it benign would
conceal a limitation instead of evaluating it.

Other controls include ordinary payments, cross-currency paths, late returns,
insufficient senders, amount-ratio boundaries and simultaneous timestamps. Scenario
checks are not real-world precision/recall or estimates of financial-crime prevalence.
