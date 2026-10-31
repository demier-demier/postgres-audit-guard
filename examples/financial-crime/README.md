# Synthetic transaction-triage examples

This fixture exercises deterministic financial-crime **investigation patterns**, including a legitimate business flow that intentionally triggers an alert. A match is a lead for an analyst, not a finding that an account holder committed a crime. No money is moved and no bank system is contacted.

`transfers.jsonl` contains **58 original synthetic transfers across 12 scenarios**. Account labels, amounts, timestamps and business explanations were authored for this repository. No customer records, private employer data or external datasets were used. These examples are distributed under the repository's license.

`expected.json` records the scripted scenario labels and expected rule matches. The labels are author-defined test context, not classifications learned from real cases. The detector receives only the six transaction fields; it does not receive these labels or the business explanations.

## Input format

Each newline-delimited JSON record has exactly these fields:

```json
{"id":"example-01","timestamp":"2026-01-15T10:00:00Z","from_account":"example-a","to_account":"example-b","amount_minor":100000,"currency":"EUR"}
```

- `id`: unique transaction identifier within the extract.
- `timestamp`: RFC 3339 timestamp. The fixture is sorted by timestamp and ID for reproducibility; ID order cannot resolve equal-time causality.
- `from_account`, `to_account`: synthetic account identifiers, not asserted identities or beneficial owners.
- `amount_minor`: positive integer minor currency units, fitting in `u64`. For example, 100000 EUR minor units represents EUR 1,000.00.
- `currency`: three uppercase letters. All examples use EUR or USD; amounts in different currencies are never combined or converted.

Opening balances, full account histories, transaction purposes, FX trades, refunds, account ownership and customer due diligence are absent. Observed outflow may therefore exceed observed inflow without establishing an accounting error. This extract is not a complete ledger.

## Expected patterns and controls

The configured window is 60 minutes. TF001 requires at least three distinct senders and subsequent outgoing transfers totaling at least 80% of the collected amount inside that window. At each incoming timestamp it uses the maximal retrospective inflow window, then the earliest qualifying outgoing prefix, ending within 60 minutes of the oldest included inflow. It does not search every possible subset. Collection precedes distribution; equal timestamps do not establish that ordering. TF002 requires an ordered, same-currency A → B → C → A path involving three distinct accounts within 60 minutes; each subsequent amount must retain 80–100% of the preceding amount. Ratio and time boundaries are inclusive.

| Scenario | Rows | Scripted label | Expected pattern | Purpose |
| --- | ---: | --- | --- | --- |
| `baseline` | 8 | Benign | None | Salary, rent, shopping, utilities and savings. |
| `merchant` | 6 | Benign | TF001 | Three customers pay a merchant, followed by an 85% settlement. **Intentional false positive against the scenario label.** |
| `pass-through` | 6 | Synthetic suspicious | TF001 | Three sources contribute 100000 minor units; two onward payments total 90000 within 25 minutes. |
| `circle` | 4 | Synthetic suspicious | TF002 | 100000 → 95000 → 90000 returns to the initial account in 30 minutes. |
| `cross-currency-circle` | 5 | Benign | None | An apparent loop mixes EUR and USD. |
| `delayed-return` | 4 | Benign | None | The return occurs after 70 minutes. |
| `below-pass-through` | 6 | Benign | None | Only 79% leaves inside the window; a later payment must not be added. |
| `two-senders` | 5 | Benign | None | A 90% onward payment has only two funding sources. |
| `circle-amount-drop` | 3 | Benign | None | The first onward payment retains only 79%. |
| `simultaneous-circle` | 3 | Benign | None | All three timestamps are equal; row order must not invent causality. |
| `circle-boundary` | 3 | Synthetic suspicious | TF002 | Each onward payment retains exactly 80%; the loop lasts exactly 60 minutes. |
| `cross-currency-fan-in` | 5 | Benign | None | Two EUR sources plus one USD source do not make three same-currency sources. |

The expected total is **four findings: two TF001 and two TF002**. Three authored scenarios are labeled `synthetic_suspicious`; one of the nine benign scenarios intentionally alerts. These are fixture expectations, not empirical fraud-detection accuracy or production performance measurements.

Local CLI validation returned those four findings with exact rule IDs and transaction-ID sequences matching `expected.json`; all eight negative scenarios produced no findings. The intentionally benign merchant alert was retained. Verification against the separately captured report digest also passed. The validated input contains 9,050 bytes with SHA-256 `2c073422ea1a42bfaf2a613b05487b681ab6f95e760919933de161574f93730c`. This is a small synthetic functional check, not a performance benchmark or a real-world accuracy study.

## Reproduce locally

From the repository root, use a new output directory. The CLI refuses to overwrite an existing report:

```sh
triage_run="$(mktemp -d)"
cargo run --locked -- triage-transfers \
  --input examples/financial-crime/transfers.jsonl \
  --output "$triage_run/report.json"
```

The command prints the SHA-256 of the exact report bytes. Preserve that digest through a separate trusted channel. To verify report integrity and replay the deterministic analysis, replace the placeholder with that separately retained digest:

```sh
cargo run --locked -- verify-transfer-report \
  --input examples/financial-crime/transfers.jsonl \
  --report "$triage_run/report.json" \
  --anchor 'REPLACE_WITH_SEPARATELY_RETAINED_REPORT_SHA256'
```

Check the exact expected rule IDs and evidence sequences:

```sh
python3 - "$triage_run/report.json" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
expected = json.loads(Path("examples/financial-crime/expected.json").read_text())
wanted = Counter(
    (rule, tuple(scenario["expected_pattern_transaction_ids"]))
    for scenario in expected["scenarios"]
    for rule in scenario["expected_rule_ids"]
)
observed = Counter(
    (alert["rule_id"], tuple(alert["source_record_ids"]))
    for alert in report["alerts"]
)
assert report["input_records"] == expected["records"]
assert observed == wanted, (observed, wanted)
print("All authored pattern expectations match, including the benign merchant alert.")
PY
```

Replay verifies agreement with the current rule implementation and exact input bytes. It does not authenticate the origin of a bank extract, establish the business explanation, or establish a crime. An attacker who can replace both the files and the supposed external digest can replace the entire story.

For an optional real PostgreSQL integration, with PostgreSQL 15+ installed and `pg_config` available:

```sh
lab_parent="$(mktemp -d /tmp/transfer-lab.XXXXXX)"
python3 scripts/run_postgres_lab.py \
  --work-dir "$lab_parent/run" \
  --transfers examples/financial-crime/transfers.jsonl
cargo run --locked -- triage-transfers \
  --input "$lab_parent/run/postgres-transfers.jsonl" \
  --output "$lab_parent/run/transfer-report.json"
```

The lab creates its own socket-only local cluster, imports the authored records into JSONB and exports them through PostgreSQL. JSON formatting can change, so the exported source hash can differ while the field values and pattern matches remain the same. The script verifies round-trip values; this does not demonstrate a deployed bank connection or a production ingestion pipeline.

## Why the benign merchant matters

Customer collections followed by a payment-processor settlement can look like rapid fund consolidation. The rule should match that observable pattern. The investigator must then establish the business explanation through independent evidence; a timestamp-and-amount rule cannot do so.

This example deliberately exposes that ambiguity instead of hiding it behind a perfect score. Do not treat its alert as guilt, blacklist an account, block a transaction or generate an external report automatically. Conversely, absence of a match means only that these two narrow rules did not match this extract. It does not establish that activity is legitimate.

For an evaluation, compare each returned rule ID and its transaction IDs with `expected.json`; inspect both the authored suspicious cases and the merchant false positive. Keep rule-match correctness separate from scenario-label interpretation. Real deployment would require independently labeled data, authorization, operational controls, and contextual analyst review; none is demonstrated by this fixture.
