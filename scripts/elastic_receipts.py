"""Classify validated ECS batches before handing accepted records to Filebeat."""

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory


MAX_BYTES = 16 * 1024 * 1024
MAX_BATCHES = 2_000
MAX_PAGES = 32_768
APPLICATION_ID = 0x50414752
SCHEMA = """
CREATE TABLE batches(
    id TEXT PRIMARY KEY,
    input_hash TEXT NOT NULL,
    input_records INTEGER NOT NULL,
    within_batch_duplicates INTEGER NOT NULL
);
CREATE TABLE documents(
    id TEXT PRIMARY KEY,
    payload BLOB NOT NULL,
    hash TEXT NOT NULL,
    first_batch TEXT NOT NULL REFERENCES batches(id)
);
CREATE TABLE receipts(
    batch TEXT NOT NULL REFERENCES batches(id),
    ordinal INTEGER NOT NULL,
    document TEXT NOT NULL REFERENCES documents(id),
    disposition TEXT NOT NULL CHECK(disposition IN ('accepted', 'replay', 'conflict')),
    observed_hash TEXT NOT NULL,
    rejected_payload BLOB,
    CHECK ((disposition = 'conflict') = (rejected_payload IS NOT NULL)),
    PRIMARY KEY (batch, ordinal)
);
"""


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bounded_read(path):
    require(path.is_file(), "Input must be a regular file")
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, "Input exceeds 16 MiB")
    return data


def prepare(binary, source):
    with TemporaryDirectory(prefix="pag-validate-") as temp:
        staged, ready = Path(temp) / "source.ndjson", Path(temp) / "ready.ndjson"
        staged.write_bytes(source)
        result = subprocess.run(
            [str(binary.resolve()), "prepare-elastic", "--input", str(staged), "--output", str(ready)],
            capture_output=True, check=False, timeout=60,
        )
        require(result.returncode == 0, "Rust ECS validation rejected the batch")
        summary = json.loads(result.stdout)
        canonical = bounded_read(ready)
        require(summary["schema"] == "elastic-prepare-result/v1"
                and summary["input_sha256"] == digest(source)
                and summary["output_sha256"] == digest(canonical), "Invalid validation receipt")
        rows = [(json.loads(line)["event"]["id"], line) for line in canonical.splitlines(keepends=True)]
        require(len(rows) == summary["unique_documents"], "Validator count mismatch")
        return rows, summary


def init(path):
    # Refuse an existing pathname, including an existing symbolic link.
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with closing(sqlite3.connect(str(path))) as db:
        db.executescript(
            f"PRAGMA page_size=4096; BEGIN IMMEDIATE; {SCHEMA}"
            f"PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version=1; COMMIT;"
        )


def connect(path, write):
    require(path.is_file() and not path.is_symlink(), "Expected an initialized local receipt journal")
    mode = "rw" if write else "ro"
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=" + mode, uri=True, timeout=5)
    try:
        require(db.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
                and db.execute("PRAGMA user_version").fetchone()[0] == 1,
                "Unsupported receipt journal")
        if write:
            require(db.execute("PRAGMA page_size").fetchone()[0] == 4096, "Unexpected journal page size")
            require(db.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete",
                    "Expected SQLite rollback journal mode")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            require(db.execute(f"PRAGMA max_page_count={MAX_PAGES}").fetchone()[0] == MAX_PAGES,
                    "Receipt journal exceeds its page cap")
    except BaseException:
        db.close()
        raise
    return db


def receipt(db, batch):
    info = db.execute(
        "SELECT input_hash, input_records, within_batch_duplicates FROM batches WHERE id=?", (batch,)
    ).fetchone()
    require(info is not None, "Unknown batch ID")
    rows = db.execute(
        """SELECT r.document, r.disposition, r.observed_hash, d.hash, d.first_batch
           FROM receipts r JOIN documents d ON d.id=r.document
           WHERE r.batch=? ORDER BY r.ordinal""", (batch,),
    )
    counts = dict.fromkeys(("accepted", "replay", "conflict"), 0)
    events = []
    for document, disposition, observed, accepted, first_batch in rows:
        counts[disposition] += 1
        events.append({"document_id": document, "disposition": disposition,
                       "observed_sha256": observed, "accepted_sha256": accepted,
                       "first_batch": first_batch})
    return {"schema": "elastic-receipt/v1", "batch": batch, "input_sha256": info[0],
            "input_records": info[1], "within_batch_duplicates": info[2],
            "counts": counts, "events": events}


def submit(path, batch, binary, source_path):
    source = bounded_read(source_path)
    rows, summary = prepare(binary, source)
    with closing(connect(path, write=True)) as db:
        with db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT input_hash FROM batches WHERE id=?", (batch,)).fetchone()
            if previous is not None:
                require(previous[0] == summary["input_sha256"], "Batch ID already binds different input bytes")
                return receipt(db, batch)
            require(db.execute("SELECT count(*) FROM batches").fetchone()[0] < MAX_BATCHES,
                    "Batch limit reached; preserve and archive this journal")
            db.execute("INSERT INTO batches VALUES (?, ?, ?, ?)", (
                batch, summary["input_sha256"], summary["input_records"], summary["duplicate_records"],
            ))
            for ordinal, (document, payload) in enumerate(rows, start=1):
                observed = digest(payload)
                prior = db.execute("SELECT payload FROM documents WHERE id=?", (document,)).fetchone()
                if prior is None:
                    db.execute("INSERT INTO documents VALUES (?, ?, ?, ?)", (document, payload, observed, batch))
                    disposition = "accepted"
                else:
                    disposition = "replay" if prior[0] == payload else "conflict"
                db.execute("INSERT INTO receipts VALUES (?, ?, ?, ?, ?, ?)",
                           (batch, ordinal, document, disposition, observed,
                            payload if disposition == "conflict" else None))
            return receipt(db, batch)


def materialize(path, batch, output, conflicts=False):
    # Stage outside the final pathname. Linking commits the name without replacing
    # existing data, including when two processes request the same destination.
    from tempfile import NamedTemporaryFile

    with closing(connect(path, write=False)) as db:
        require(db.execute("SELECT 1 FROM batches WHERE id=?", (batch,)).fetchone() is not None,
                "Unknown batch ID")
        if conflicts:
            query = """SELECT rejected_payload, observed_hash FROM receipts
                       WHERE batch=? AND disposition='conflict' ORDER BY ordinal"""
        else:
            query = """SELECT d.payload, d.hash FROM receipts r JOIN documents d ON d.id=r.document
                       WHERE r.batch=? AND r.disposition='accepted' ORDER BY r.ordinal"""
        rows = db.execute(query, (batch,))
        sha = hashlib.sha256()
        count = 0
        with NamedTemporaryFile(dir=output.parent, prefix=".pag-", suffix=".tmp", delete=False) as stream:
            staged = Path(stream.name)
            try:
                for payload, expected in rows:
                    require(digest(payload) == expected, "Stored document failed its digest check")
                    stream.write(payload)
                    sha.update(payload)
                    count += 1
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
                os.link(staged, output)
            finally:
                staged.unlink()
    return {"schema": "elastic-materialization/v1", "batch": batch,
            "kind": "conflicts" if conflicts else "accepted",
            "documents": count, "output_sha256": sha.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    for command in ("submit", "receipt", "materialize", "export-conflicts"):
        action = commands.add_parser(command)
        action.add_argument("--batch", required=True)
        if command == "submit":
            action.add_argument("--input", type=Path, required=True)
            action.add_argument("--binary", type=Path, required=True)
        if command in ("materialize", "export-conflicts"):
            action.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == "init":
        init(args.journal)
        return
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.batch), "Invalid batch label")
    if args.command == "submit":
        result = submit(args.journal, args.batch, args.binary, args.input)
    elif args.command in ("materialize", "export-conflicts"):
        result = materialize(args.journal, args.batch, args.output, args.command == "export-conflicts")
    else:
        with closing(connect(args.journal, write=False)) as db:
            result = receipt(db, args.batch)
    print(json.dumps(result, sort_keys=True))
    if args.command == "submit" and result["counts"]["conflict"]:
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        sys.exit(str(error))
    except (OSError, sqlite3.Error, subprocess.SubprocessError):
        sys.exit("Receipt journal operation failed")
