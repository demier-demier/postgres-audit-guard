"""Classify validated ECS batches before handing accepted records to Filebeat."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
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
MAX_OBSERVATIONS = 2_000
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
MAX_BULK_ATTEMPTS = 2_000
MAX_BULK_ITEMS = 1_000
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
DELIVERY_SCHEMA = (
    """CREATE TABLE observations(
        id TEXT PRIMARY KEY,
        batch TEXT NOT NULL REFERENCES batches(id),
        sink_index TEXT NOT NULL,
        snapshot_hash TEXT NOT NULL
    )""",
    """CREATE TABLE delivery(
        observation TEXT NOT NULL REFERENCES observations(id),
        document TEXT NOT NULL REFERENCES documents(id),
        disposition TEXT NOT NULL CHECK(disposition IN ('confirmed', 'missing', 'mismatch')),
        expected_hash TEXT NOT NULL,
        stored_hash TEXT,
        version INTEGER,
        CHECK ((disposition = 'missing') = (stored_hash IS NULL)),
        CHECK ((stored_hash IS NULL) = (version IS NULL)),
        PRIMARY KEY (observation, document)
    )""",
)
BULK_SCHEMA = (
    """CREATE TABLE bulk_attempts(
        id TEXT PRIMARY KEY,
        batch TEXT NOT NULL REFERENCES batches(id),
        sink_index TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        response_hash TEXT NOT NULL
    )""",
    """CREATE TABLE bulk_items(
        attempt TEXT NOT NULL REFERENCES bulk_attempts(id),
        ordinal INTEGER NOT NULL,
        document TEXT NOT NULL REFERENCES documents(id),
        status INTEGER NOT NULL,
        error_type TEXT,
        disposition TEXT NOT NULL CHECK(disposition IN ('created', 'conflict', 'rejected')),
        PRIMARY KEY (attempt, ordinal),
        UNIQUE (attempt, document)
    )""",
    "CREATE INDEX bulk_scope ON bulk_attempts(batch, sink_index)",
    "CREATE INDEX bulk_errors ON bulk_items(document, attempt) WHERE disposition <> 'created'",
)


def digest(payload):
    return hashlib.sha256(payload).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bounded_read(path, limit=MAX_BYTES):
    require(path.is_file(), "Input must be a regular file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "Input exceeds its byte limit")
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
            + ";".join(DELIVERY_SCHEMA + BULK_SCHEMA)
            + f"; PRAGMA application_id={APPLICATION_ID}; PRAGMA user_version=3; COMMIT;"
        )


def connect(path, write):
    require(path.is_file() and not path.is_symlink(), "Expected an initialized local receipt journal")
    mode = "rw" if write else "ro"
    db = sqlite3.connect(path.resolve().as_uri() + "?mode=" + mode, uri=True, timeout=5)
    try:
        require(db.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
                and schema_version(db) in (1, 2, 3),
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


def schema_version(db):
    return db.execute("PRAGMA user_version").fetchone()[0]


def migrate(db, target):
    for version, statements in [(2, DELIVERY_SCHEMA), (3, BULK_SCHEMA)]:
        if schema_version(db) < version <= target:
            for statement in statements:
                db.execute(statement)
            db.execute(f"PRAGMA user_version={version}")


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


def write_payloads(rows, output):
    # Link the completed file without replacing an existing destination.
    from tempfile import NamedTemporaryFile

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
    return count, sha.hexdigest()


def accepted(db, batch):
    require(db.execute("SELECT 1 FROM batches WHERE id=?", (batch,)).fetchone() is not None,
            "Unknown batch ID")
    return db.execute(
        """SELECT d.id, d.payload, d.hash FROM receipts r JOIN documents d ON d.id=r.document
           WHERE r.batch=? AND r.disposition='accepted' ORDER BY d.id""", (batch,),
    )


def materialize(path, batch, output, conflicts=False):
    with closing(connect(path, write=False)) as db:
        require(db.execute("SELECT 1 FROM batches WHERE id=?", (batch,)).fetchone() is not None,
                "Unknown batch ID")
        if conflicts:
            query = """SELECT rejected_payload, observed_hash FROM receipts
                       WHERE batch=? AND disposition='conflict' ORDER BY ordinal"""
        else:
            query = """SELECT d.payload, d.hash FROM receipts r JOIN documents d ON d.id=r.document
                       WHERE r.batch=? AND r.disposition='accepted' ORDER BY r.ordinal"""
        count, sha = write_payloads(db.execute(query, (batch,)), output)
    return {"schema": "elastic-materialization/v1", "batch": batch,
            "kind": "conflicts" if conflicts else "accepted",
            "documents": count, "output_sha256": sha}


def normalized(document):
    """Normalize Filebeat's UTC spelling while retaining sub-microsecond digits."""
    require(type(document) is dict, "Document source must be an object")
    timestamp = document.get("@timestamp")
    match = isinstance(timestamp, str) and re.fullmatch(
        r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?(Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
        timestamp,
    )
    require(bool(match), "Timestamp is outside the comparison contract")
    base, fraction, offset = match.groups()
    instant = datetime.fromisoformat(base + offset.replace("Z", "+00:00")).astimezone(timezone.utc)
    seconds = instant.replace(tzinfo=None).isoformat(timespec="seconds")
    return {**document, "@timestamp": seconds + "." + (fraction or "").ljust(9, "0") + "Z"}


def strict_json(payload):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON member in snapshot")
            result[key] = value
        return result

    def reject_constant(_):
        raise ValueError("Non-finite number in snapshot")

    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject_constant)
    except (UnicodeError, RecursionError, ValueError) as error:
        raise ValueError("Malformed or ambiguous JSON snapshot") from error


def normalized_bytes(document):
    # Bytes retain distinctions such as JSON true vs. 1 that Python equality loses.
    try:
        return json.dumps(normalized(document), ensure_ascii=True, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("ascii")
    except (OverflowError, RecursionError) as error:
        raise ValueError("Document source exceeds the comparison limits") from error


def delivery_receipt(db, label):
    info = db.execute(
        "SELECT batch, sink_index, snapshot_hash FROM observations WHERE id=?", (label,),
    ).fetchone()
    require(info is not None, "Unknown observation label")
    rows = db.execute(
        """SELECT document, disposition, expected_hash, stored_hash, version FROM delivery
           WHERE observation=? ORDER BY document""", (label,),
    )
    counts = dict.fromkeys(("confirmed", "missing", "mismatch"), 0)
    events = []
    for document, disposition, expected, stored, version in rows:
        counts[disposition] += 1
        events.append({"document_id": document, "disposition": disposition,
                       "expected_source_sha256": expected, "stored_source_sha256": stored,
                       "stored_version": version})
    return {"schema": "elastic-delivery-observation/v1", "observation": label, "batch": info[0],
            "index": info[1], "snapshot_sha256": info[2], "counts": counts, "events": events}


def observe(path, batch, label, index, snapshot_path):
    payload = bounded_read(snapshot_path, MAX_SNAPSHOT_BYTES)
    observation_hash = digest(payload)
    response = strict_json(payload)
    require(type(response) is dict and type(response.get("docs")) is list and "error" not in response,
            "Expected a complete _mget response")

    by_id = {}
    for entry in response["docs"]:
        require(type(entry) is dict and "error" not in entry and entry.get("_index") == index,
                "Snapshot contains an error or a different index")
        key = entry.get("_id")
        require(isinstance(key, str) and re.fullmatch(r"[0-9a-f]{64}", key) and key not in by_id,
                "Snapshot contains an invalid or repeated document ID")
        found = entry.get("found")
        if found is True:
            version = entry.get("_version")
            require(type(version) is int and 1 <= version <= 2**63 - 1 and "_source" in entry,
                    "Found document lacks a valid version or full source")
            by_id[key] = (normalized_bytes(entry["_source"]), version)
        else:
            require(found is False and set(entry) == {"_id", "_index", "found"},
                    "Expected an explicit missing-document response")
            by_id[key] = (None, None)

    with closing(connect(path, write=True)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        migrate(db, 2)
        prior = db.execute("SELECT batch, sink_index, snapshot_hash FROM observations WHERE id=?", (label,)).fetchone()
        if prior is not None:
            require(prior == (batch, index, observation_hash), "Observation label already binds another capture")
            return delivery_receipt(db, label)
        require(db.execute("SELECT count(*) FROM observations").fetchone()[0] < MAX_OBSERVATIONS,
                "Observation limit reached; preserve and archive this journal")
        db.execute("INSERT INTO observations VALUES (?, ?, ?, ?)", (label, batch, index, observation_hash))
        for key, canonical, expected_hash in accepted(db, batch):
            require(key in by_id, "Snapshot does not cover every accepted document")
            require(digest(canonical) == expected_hash, "Stored document failed its digest check")
            expected = normalized_bytes(json.loads(canonical))
            stored, version = by_id.pop(key)
            if stored is None:
                disposition = "missing"
            else:
                disposition = "confirmed" if stored == expected and version == 1 else "mismatch"
            db.execute("INSERT INTO delivery VALUES (?, ?, ?, ?, ?, ?)", (
                label, key, disposition, digest(expected), digest(stored) if stored is not None else None, version,
            ))
        require(not by_id, "Snapshot contains documents outside the accepted batch")
        return delivery_receipt(db, label)


def recover(db, label, output):
    info = delivery_receipt(db, label)
    require(db.execute(
        "SELECT id FROM observations WHERE batch=? AND sink_index=? ORDER BY rowid DESC LIMIT 1",
        (info["batch"], info["index"]),
    ).fetchone()[0] == label, "Recovery requires the latest recorded observation for this batch and index")
    query = """SELECT d.id, d.payload, d.hash FROM delivery r JOIN documents d ON d.id=r.document
               WHERE r.observation=? AND r.disposition='missing' ORDER BY r.document"""
    withheld = set()
    if schema_version(db) >= 3:
        withheld = {row[0] for row in db.execute(
            """SELECT DISTINCT i.document FROM bulk_attempts a JOIN bulk_items i ON i.attempt=a.id
               JOIN delivery r ON r.document=i.document AND r.observation=?
               WHERE a.batch=? AND a.sink_index=? AND r.disposition='missing' AND i.disposition <> 'created'""",
            (label, info["batch"], info["index"]),
        )}
    rows = ((payload, sha) for document, payload, sha in db.execute(query, (label,)) if document not in withheld)
    count, sha = write_payloads(rows, output)
    result = {"schema": "elastic-delivery-recovery/v1", "observation": label, "batch": info["batch"],
              "index": info["index"], "documents": count, "output_sha256": sha}
    if withheld:
        result["withheld_bulk_failures"] = sorted(withheld)
    return result


def bulk_request(db, batch, index, documents, output):
    require(1 <= len(documents) <= MAX_BULK_ITEMS and len(set(documents)) == len(documents),
            "Select one to 1,000 distinct document IDs")
    selected = set(documents)
    chunks = {}
    size = 0
    for document, payload, sha in accepted(db, batch):
        if document in selected:
            require(digest(payload) == sha, "Stored document failed its digest check")
            action = {"create": {"_id": document, "_index": index}}
            entry = json.dumps(action, separators=(",", ":")).encode("ascii") + b"\n" + payload
            size += len(entry)
            require(size <= MAX_BYTES, "Bulk request exceeds its byte limit")
            chunks[document] = entry
    require(chunks.keys() == selected, "Requested documents must have been accepted in this batch")
    count, sha = write_payloads(((chunks[key], digest(chunks[key])) for key in documents), output)
    return {"schema": "elastic-bulk-request/v1", "batch": batch, "index": index,
            "documents": count, "request_sha256": sha}


def bulk_results(request, response, index):
    require(request.endswith(b"\n"), "Bulk request requires a trailing LF")
    lines = request[:-1].split(b"\n", 2 * MAX_BULK_ITEMS)
    require(2 <= len(lines) <= 2 * MAX_BULK_ITEMS and len(lines) % 2 == 0, "Invalid bulk request item count")
    response = strict_json(response)
    require(type(response) is dict and type(response.get("items")) is list
            and "error" not in response and len(response["items"]) * 2 == len(lines)
            and type(response.get("errors")) is bool,
            "Bulk response must include one item per create")
    seen = set()
    any_errors = False
    for ordinal, item in enumerate(response["items"], start=1):
        action, source = map(strict_json, lines[(ordinal - 1) * 2:ordinal * 2])
        require(type(action) is dict and set(action) == {"create"}, "Only create actions are supported")
        target = action["create"]
        require(type(target) is dict and set(target) == {"_id", "_index"} and target["_index"] == index,
                "Bulk request must use the selected concrete index and ID")
        key = target["_id"]
        require(isinstance(key, str) and re.fullmatch(r"[0-9a-f]{64}", key) and key not in seen,
                "Bulk request has an invalid or repeated document ID")
        seen.add(key)
        require(type(item) is dict and set(item) == {"create"} and type(item["create"]) is dict,
                "Unexpected bulk response action")
        result = item["create"]
        require(result.get("_id") == key and result.get("_index") == index,
                "Bulk response index or document order does not match")
        status = result.get("status")
        kind = None
        if type(status) is int and status == 201:
            require("error" not in result and result.get("result") == "created"
                    and type(result.get("_version")) is int and result["_version"] == 1,
                    "Bulk create confirmation is ambiguous")
            disposition = "created"
        else:
            any_errors = True
            error = result.get("error")
            require(type(status) is int and 400 <= status < 600 and type(error) is dict,
                    "Unsupported bulk item status")
            kind = error.get("type")
            require(isinstance(kind, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,79}", kind),
                    "Bulk error lacks a supported type")
            disposition = "conflict" if status == 409 and kind == "version_conflict_engine_exception" else "rejected"
        yield ordinal, key, normalized_bytes(source), status, kind, disposition
    require(response["errors"] == any_errors, "Bulk errors flag contradicts the item results")


def bulk_receipt(db, label):
    info = db.execute("SELECT batch, sink_index, request_hash, response_hash FROM bulk_attempts WHERE id=?",
                      (label,)).fetchone()
    require(info is not None, "Unknown bulk attempt label")
    items = [{"document_id": key, "status": status, "error_type": error, "disposition": disposition}
             for key, status, error, disposition in db.execute(
                 "SELECT document, status, error_type, disposition FROM bulk_items WHERE attempt=? ORDER BY ordinal",
                 (label,),
             )]
    counts = {name: sum(row["disposition"] == name for row in items) for name in ("created", "conflict", "rejected")}
    return {"schema": "elastic-bulk-receipt/v1", "attempt": label, "batch": info[0], "index": info[1],
            "request_sha256": info[2], "response_sha256": info[3], "counts": counts, "items": items}


def record_bulk(path, batch, label, index, request_path, response_path):
    request = bounded_read(request_path)
    response = bounded_read(response_path)
    identity = (batch, index, digest(request), digest(response))
    with closing(connect(path, write=True)) as db, db:
        db.execute("BEGIN IMMEDIATE")
        migrate(db, 3)
        prior = db.execute("SELECT batch, sink_index, request_hash, response_hash FROM bulk_attempts WHERE id=?",
                           (label,)).fetchone()
        if prior is not None:
            require(prior == identity, "Bulk attempt label already binds another capture")
            return bulk_receipt(db, label)
        require(db.execute("SELECT count(*) FROM bulk_attempts").fetchone()[0] < MAX_BULK_ATTEMPTS,
                "Bulk attempt limit reached; preserve and archive this journal")
        db.execute("INSERT INTO bulk_attempts VALUES (?, ?, ?, ?, ?)", (label, *identity))
        for ordinal, key, source, status, kind, disposition in bulk_results(request, response, index):
            stored = db.execute("SELECT payload, hash FROM documents WHERE id=? AND first_batch=?", (key, batch)).fetchone()
            require(stored is not None and digest(stored[0]) == stored[1]
                    and source == normalized_bytes(json.loads(stored[0])),
                    "Bulk source is not the accepted payload for this batch")
            db.execute("INSERT INTO bulk_items VALUES (?, ?, ?, ?, ?, ?)",
                       (label, ordinal, key, status, kind, disposition))
        return bulk_receipt(db, label)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    for command in ("submit", "receipt", "materialize", "export-conflicts", "delivery-query",
                    "observe-delivery", "delivery-receipt", "recover-missing",
                    "bulk-request", "record-bulk", "bulk-receipt"):
        action = commands.add_parser(command)
        if command not in ("delivery-receipt", "recover-missing", "bulk-receipt"):
            action.add_argument("--batch", required=True)
        if command in ("observe-delivery", "delivery-receipt", "recover-missing"):
            action.add_argument("--observation", required=True)
        if command in ("observe-delivery", "bulk-request", "record-bulk"):
            action.add_argument("--index", required=True)
        if command == "observe-delivery":
            action.add_argument("--snapshot", type=Path, required=True)
        if command in ("record-bulk", "bulk-receipt"):
            action.add_argument("--attempt", required=True)
        if command == "record-bulk":
            action.add_argument("--request", type=Path, required=True)
            action.add_argument("--response", type=Path, required=True)
        if command == "bulk-request":
            action.add_argument("--document", action="append", required=True)
        if command == "submit":
            action.add_argument("--input", type=Path, required=True)
            action.add_argument("--binary", type=Path, required=True)
        if command in ("materialize", "export-conflicts", "recover-missing", "bulk-request"):
            action.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == "init":
        init(args.journal)
        return
    for name in ("batch", "observation", "attempt"):
        label = getattr(args, name, None)
        require(label is None or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", label),
                "Invalid " + name + " label")
    if getattr(args, "index", None) is not None:
        require(re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,254}", args.index), "Expected a concrete index name")
    if args.command == "submit":
        result = submit(args.journal, args.batch, args.binary, args.input)
    elif args.command in ("materialize", "export-conflicts"):
        result = materialize(args.journal, args.batch, args.output, args.command == "export-conflicts")
    elif args.command == "observe-delivery":
        result = observe(args.journal, args.batch, args.observation, args.index, args.snapshot)
    elif args.command == "record-bulk":
        result = record_bulk(args.journal, args.batch, args.attempt, args.index, args.request, args.response)
    else:
        with closing(connect(args.journal, write=False)) as db, db:
            db.execute("BEGIN")
            if args.command == "receipt":
                result = receipt(db, args.batch)
            elif args.command == "delivery-query":
                result = {"ids": [key for key, _, _ in accepted(db, args.batch)]}
            elif args.command == "bulk-request":
                result = bulk_request(db, args.batch, args.index, args.document, args.output)
            elif args.command == "bulk-receipt":
                require(schema_version(db) >= 3, "No bulk attempts recorded")
                result = bulk_receipt(db, args.attempt)
            else:
                require(schema_version(db) >= 2, "No delivery observations recorded")
                if args.command == "delivery-receipt":
                    result = delivery_receipt(db, args.observation)
                else:
                    result = recover(db, args.observation, args.output)
    print(json.dumps(result, sort_keys=True))
    if args.command == "submit" and result["counts"]["conflict"]:
        sys.exit(2)
    if args.command == "record-bulk" and (result["counts"]["conflict"] or result["counts"]["rejected"]):
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except ValueError as error:
        sys.exit(str(error))
    except (OSError, sqlite3.Error, subprocess.SubprocessError):
        sys.exit("Receipt journal operation failed")
