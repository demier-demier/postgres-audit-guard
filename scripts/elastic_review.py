"""Record operator review of held bulk items and reconstruct explicitly approved spools."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import re
import sqlite3
import sys

import elastic_receipts as journal


def basis(db, attempt, document, observation):
    failure = db.execute(
        """SELECT a.rowid, a.batch, a.sink_index, a.request_hash, a.response_hash, i.status, i.error_type
           FROM bulk_attempts a JOIN bulk_items i ON i.attempt=a.id
           WHERE a.id=? AND i.document=? AND i.disposition <> 'created'""", (attempt, document),
    ).fetchone()
    journal.require(failure is not None, "Review requires a recorded failed bulk item")
    sequence, batch, index, request_hash, response_hash, status, error = failure
    latest = db.execute(
        """SELECT a.id FROM bulk_attempts a JOIN bulk_items i ON i.attempt=a.id
           WHERE a.batch=? AND a.sink_index=? AND i.document=? ORDER BY a.rowid DESC LIMIT 1""",
        (batch, index, document),
    ).fetchone()
    journal.require(latest[0] == attempt, "A newer bulk result supersedes the selected failure")
    observed = db.execute(
        """SELECT o.snapshot_hash, o.bulk_watermark, d.disposition, d.expected_hash
           FROM observations o JOIN delivery d ON d.observation=o.id
           WHERE o.id=? AND o.batch=? AND o.sink_index=? AND d.document=?""",
        (observation, batch, index, document),
    ).fetchone()
    journal.require(observed is not None and observed[2] == "missing",
                    "Review requires explicit absence in the same batch and index")
    current_observation = db.execute(
        "SELECT id FROM observations WHERE batch=? AND sink_index=? ORDER BY rowid DESC LIMIT 1", (batch, index),
    ).fetchone()[0]
    watermark = db.execute("SELECT MAX(rowid) FROM bulk_attempts WHERE batch=? AND sink_index=?",
                           (batch, index)).fetchone()[0]
    journal.require(current_observation == observation and observed[1] == watermark and observed[1] >= sequence,
                    "Review requires a fresh observation after the latest recorded bulk result")
    payload, source_hash = db.execute("SELECT payload, hash FROM documents WHERE id=?", (document,)).fetchone()
    journal.require(journal.digest(payload) == source_hash
                    and journal.digest(journal.normalized_bytes(json.loads(payload))) == observed[3],
                    "Review source failed its digest check")
    context = {"batch": batch, "index": index, "document_id": document, "attempt": attempt,
               "request_sha256": request_hash, "response_sha256": response_hash, "status": status, "error_type": error,
               "observation": observation, "snapshot_sha256": observed[0], "bulk_watermark": watermark,
               "source_sha256": source_hash}
    serialized = json.dumps(context, sort_keys=True, separators=(",", ":")).encode("ascii")
    return journal.digest(serialized), context, payload


def show(db, label):
    row = db.execute(
        "SELECT attempt, document, observation, actor, decision, reason, basis_hash FROM bulk_reviews WHERE id=?",
        (label,),
    ).fetchone()
    journal.require(row is not None, "Unknown review label")
    return {"schema": "elastic-bulk-review/v1", "review": label, **dict(zip(
        ("attempt", "document_id", "observation", "actor", "decision", "reason", "basis_sha256"), row,
    )), "actor_identity": "operator-declared"}


def record(db, label, attempt, document, observation, actor, decision, reason):
    journal.require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", actor), "Use a pseudonymous actor label")
    journal.require((decision, reason) in {
        ("retry", "policy-corrected"), ("retry", "transient-failure-investigated"),
        ("hold", "investigation-required"),
    }, "Decision and reason are outside the supported review policy")
    journal.migrate(db, 4)
    previous = db.execute("SELECT attempt, document, observation, actor, decision, reason FROM bulk_reviews WHERE id=?",
                          (label,)).fetchone()
    if previous is not None:
        journal.require(previous == (attempt, document, observation, actor, decision, reason),
                        "Review label already binds another decision")
        return show(db, label)
    journal.require(db.execute("SELECT count(*) FROM bulk_reviews").fetchone()[0] < journal.MAX_REVIEWS,
                    "Review limit reached; preserve and archive this journal")
    digest, _, _ = basis(db, attempt, document, observation)
    db.execute("INSERT INTO bulk_reviews VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
               (label, attempt, document, observation, actor, decision, reason, digest))
    return show(db, label)


def materialize(db, label, output):
    review = show(db, label)
    journal.require(review["decision"] == "retry", "The selected review holds this item")
    latest = db.execute(
        """SELECT r.id FROM bulk_reviews r JOIN bulk_attempts a ON a.id=r.attempt
           WHERE r.document=? AND (a.batch, a.sink_index) = (
             SELECT batch, sink_index FROM bulk_attempts WHERE id=?
           ) ORDER BY r.rowid DESC LIMIT 1""", (review["document_id"], review["attempt"]),
    ).fetchone()[0]
    journal.require(latest == label, "A later review supersedes this decision")
    digest, context, payload = basis(db, review["attempt"], review["document_id"], review["observation"])
    journal.require(digest == review["basis_sha256"], "Review basis no longer matches the recorded evidence")
    count, sha = journal.write_payloads([(payload, context["source_sha256"])], output)
    return {"schema": "elastic-reviewed-spool/v1", "review": label, "documents": count,
            "output_sha256": sha, "batch": context["batch"], "index": context["index"],
            "document_id": review["document_id"], "basis_sha256": digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("record", "show", "materialize"):
        command = commands.add_parser(name)
        command.add_argument("--review", required=True)
        if name == "record":
            for field in ("attempt", "document", "observation", "actor", "decision", "reason"):
                command.add_argument("--" + field, required=True)
        if name == "materialize":
            command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for field in ("review", "attempt", "observation"):
        label = getattr(args, field, None)
        journal.require(label is None or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", label),
                        "Invalid " + field + " label")
    with closing(journal.connect(args.journal, write=args.command != "show")) as db, db:
        # Serializes reviews and publication of the completed spool against new evidence.
        db.execute("BEGIN" if args.command == "show" else "BEGIN IMMEDIATE")
        if args.command == "record":
            result = record(db, args.review, args.attempt, args.document, args.observation,
                            args.actor, args.decision, args.reason)
        else:
            journal.require(journal.schema_version(db) >= 4, "No bulk reviews recorded")
            result = show(db, args.review) if args.command == "show" else materialize(db, args.review, args.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        os.umask(0o077)
        main()
    except ValueError as error:
        sys.exit(str(error))
    except (OSError, sqlite3.Error):
        sys.exit("Bulk review operation failed")
