# Recorded synthetic analyst workflow

These snapshots were produced by actual Rust CLI processes on 2026-11-03 after
58 original synthetic transfers were imported into and exported from a fresh,
socket-only PostgreSQL 15.17 cluster. The cluster stopped after the lab. Exported
source bytes exactly matched the [existing public fixture](../financial-crime/observed/postgres-transfers.jsonl)
and produced the same [anchored transfer report](../financial-crime/observed/report.json).

The note contents, analyst tokens and review times are scripted fixture data.
There are no real customers, investigators or financial-crime allegations.

| Snapshot | Scripted review state | What remains preserved |
| --- | --- | --- |
| [Merchant v1](merchant-v1.json) | Open | Report and alert binding, opening note and source references |
| [Merchant v2](merchant-v2.json) | Needs information | Original review and request for context |
| [Merchant v3](merchant-v3.json) | Closed with explanation | Legitimate-settlement context and previous reviews |
| [Merchant v4](merchant-v4.json) | Reopened | All prior notes, including the closure explanation |
| [Referral v1](referral-v1.json) | Open | Separate synthetic pass-through alert and opening note |
| [Referral v2](referral-v2.json) | Escalated for review | Manual workflow label; no outbound referral or account action |

All four original detector alerts remain unchanged. Closing an explained case
never removes its signal or establishes that similar future activity is safe.
All six snapshots passed separate invocations of the same Rust CLI verifier. See
[workflow output](workflow-result.json), [local test observations](validation.json)
and [reproduction and threat model](../../docs/ANALYST-CASES.md).

Digests stored next to these example files are reproduction aids, not independent
trusted anchors. A real operator must retain anchors and the current case head
through an independently protected process. Actor identity, note truth, collection
authenticity, completeness and legal admissibility are not established by hashes.
