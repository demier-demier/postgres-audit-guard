"""Bulk correlation and recovery tests against private temporary journals."""

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import elastic_receipts as journal


class MixedBulkReceipt(unittest.TestCase):
    index = "fixture-index"
    attempt = "test-attempt"

    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.db = self.root / "journal.db"
        self.request = self.root / "bulk.ndjson"
        self.response = self.root / "bulk.json"
        self.ids = [char * 64 for char in "abcd"]
        self.docs = {
            key: {"event": {"id": key}, "@timestamp": "2026-01-02T03:04:05.123456789Z"}
            for key in self.ids
        }
        # Model an existing v2 journal, with evidence retained through migration.
        with closing(sqlite3.connect(self.db)) as db, db:
            db.executescript(journal.SCHEMA + ";".join(journal.DELIVERY_SCHEMA))
            db.execute(f"PRAGMA application_id={journal.APPLICATION_ID}")
            db.execute("PRAGMA user_version=2")
            db.execute("INSERT INTO batches VALUES ('initial', 'fixture-hash', 4, 0)")
            for ordinal, (key, source) in enumerate(self.docs.items(), 1):
                payload = json.dumps(source).encode() + b"\n"
                digest = journal.digest(payload)
                db.execute("INSERT INTO documents VALUES (?, ?, ?, 'initial')", (key, payload, digest))
                db.execute("INSERT INTO receipts VALUES ('initial', ?, ?, 'accepted', ?, NULL)", (ordinal, key, digest))
        with closing(journal.connect(self.db, write=False)) as db:
            self.request_info = journal.bulk_request(db, "initial", self.index, self.ids[:3], self.request)
        self.items = [{"create": {"_id": key, "_index": self.index, "status": status}}
                      for key, status in zip(self.ids, (201, 409, 400))]
        self.items[0]["create"].update(result="created", _version=1)
        self.items[1]["create"]["error"] = {"type": "version_conflict_engine_exception"}
        self.items[2]["create"]["error"] = {"type": "fail_processor_exception", "reason": "PRIVATE-FIXTURE-CONTENT"}

    def capture(self, items, errors=True):
        self.response.write_text(json.dumps({"errors": errors, "items": items}))
        return journal.record_bulk(self.db, "initial", self.attempt, self.index, self.request, self.response)

    def test_receipt_migrates_and_binds_both_captures(self):
        mixed = self.capture(self.items)
        self.assertEqual(mixed["counts"], {"created": 1, "conflict": 1, "rejected": 1})
        self.assertEqual(mixed["request_sha256"], self.request_info["request_sha256"])
        self.assertEqual(mixed["response_sha256"], journal.digest(self.response.read_bytes()))
        self.assertEqual(mixed, self.capture(self.items))
        self.assertNotIn("PRIVATE-FIXTURE-CONTENT", json.dumps(mixed))
        with closing(journal.connect(self.db, write=False)) as db:
            self.assertEqual(journal.schema_version(db), 3)
            self.assertEqual(journal.bulk_receipt(db, self.attempt), mixed)
            self.assertEqual(journal.receipt(db, "initial")["counts"]["accepted"], 4)
        with self.assertRaisesRegex(ValueError, "already binds"):
            self.capture(self.items, errors=False)

    def test_bulk_request_is_create_only_and_refuses_replacement(self):
        rows = [json.loads(line) for line in self.request.read_bytes().splitlines()]
        self.assertEqual(rows[::2], [{"create": {"_id": key, "_index": self.index}} for key in self.ids[:3]])
        self.assertEqual(rows[1::2], [self.docs[key] for key in self.ids[:3]])
        with closing(journal.connect(self.db, write=False)) as db:
            with self.assertRaises(FileExistsError):
                journal.bulk_request(db, "initial", self.index, self.ids, self.request)
            with self.assertRaisesRegex(ValueError, "distinct"):
                journal.bulk_request(db, "initial", self.index, self.ids[:1] * 2, self.root / "repeated.ndjson")
        self.assertEqual(self.request_info["request_sha256"], journal.digest(self.request.read_bytes()))

    def test_incomplete_out_of_order_and_contradictory_batches_rollback(self):
        wrong_index = {"create": {**self.items[-1]["create"], "_index": "different-index"}}
        wrong_status = {"create": {**self.items[-1]["create"], "status": True}}
        for items, errors in [
            (self.items[:-1], True),
            (list(reversed(self.items)), True),
            (self.items[:2] + [wrong_index], True),
            (self.items[:2] + [wrong_status], True),
            (self.items, False),
        ]:
            with self.subTest(items=items, errors=errors), self.assertRaises(ValueError):
                self.capture(items, errors)
        with closing(journal.connect(self.db, write=False)) as db:
            self.assertEqual(journal.schema_version(db), 2)
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='bulk_attempts'").fetchone())

    def test_changed_request_payload_is_rejected_even_with_matching_response(self):
        before = self.request.read_bytes()
        self.request.write_bytes(before.replace(b"03:04:05", b"03:04:06"))
        with self.assertRaisesRegex(ValueError, "not the accepted payload"):
            self.capture(self.items)
        with closing(journal.connect(self.db, write=False)) as db:
            self.assertEqual(journal.schema_version(db), 2)

    def test_transient_status_is_retained_as_an_item_failure(self):
        retry = {"create": {**self.items[-1]["create"], "status": 429,
                             "error": {"type": "es_rejected_execution_exception"}}}
        row = self.capture(self.items[:2] + [retry])["items"][-1]
        self.assertEqual((row["status"], row["disposition"]), (429, "rejected"))

    def test_scoped_recovery_withholds_prior_failures_without_dropping_other_missing_ids(self):
        self.capture(self.items)
        for index, label in [(self.index, "target"), ("other-index", "other")]:
            key = self.ids[0]
            docs = [{"_id": key, "_index": index, "_version": 1, "found": True, "_source": self.docs[key]}]
            docs += [{"_id": key, "_index": index, "found": False} for key in self.ids[1:]]
            snapshot = self.root / "mget.json"
            snapshot.write_text(json.dumps({"docs": docs}))
            journal.observe(self.db, "initial", label, index, snapshot)
        with closing(journal.connect(self.db, write=False)) as db:
            recovered = self.root / "recovery.ndjson"
            held = journal.recover(db, "target", recovered)
            self.assertEqual(held["withheld_bulk_failures"], self.ids[1:3])
            self.assertEqual([json.loads(line)["event"]["id"] for line in recovered.read_bytes().splitlines()],
                             self.ids[3:])
            other = journal.recover(db, "other", self.root / "other-recovery.ndjson")
            self.assertEqual(other["documents"], 3)
            self.assertNotIn("withheld_bulk_failures", other)


if __name__ == "__main__":
    unittest.main()
