"""Bulk correlation and recovery tests against private temporary journals."""

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import elastic_receipts as journal
import elastic_review as review


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
            self.assertEqual(journal.schema_version(db), 4)
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

    def observe_missing(self, label):
        snapshot = self.root / "missing.json"
        snapshot.write_text(json.dumps({"docs": [
            {"_id": key, "_index": self.index, "found": False} for key in self.ids
        ]}))
        return journal.observe(self.db, "initial", label, self.index, snapshot)

    def review(self, label, observation, decision="retry", attempt=None):
        with closing(journal.connect(self.db, write=True)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            return review.record(db, label, attempt or self.attempt, self.ids[2], observation, "reviewer-1", decision,
                                 "policy-corrected" if decision == "retry" else "investigation-required")

    def export_review(self, label, output):
        with closing(journal.connect(self.db, write=True)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            return review.materialize(db, label, output)

    def test_review_preserves_exact_basis_and_exports_only_selected_source(self):
        self.capture(self.items)
        self.observe_missing("after-failure")
        recorded = self.review("approved", "after-failure")
        self.assertEqual(self.review("approved", "after-failure"), recorded)
        with closing(journal.connect(self.db, write=False)) as db:
            self.assertEqual(review.show(db, "approved"), recorded)
        out = self.root / "approved.ndjson"
        materialized = self.export_review("approved", out)
        self.assertEqual(materialized["documents"], 1)
        self.assertEqual(json.loads(out.read_bytes()), self.docs[self.ids[2]])
        self.assertEqual(materialized["basis_sha256"], recorded["basis_sha256"])
        with self.assertRaises(FileExistsError):
            self.export_review("approved", out)
        with self.assertRaisesRegex(ValueError, "already binds"):
            self.review("approved", "after-failure", decision="hold")

    def test_later_hold_revokes_export_of_an_earlier_retry_decision(self):
        self.capture(self.items)
        self.observe_missing("after-failure")
        self.review("approved", "after-failure")
        self.review("held", "after-failure", decision="hold")
        with self.assertRaisesRegex(ValueError, "later review"):
            self.export_review("approved", self.root / "superseded.ndjson")
        with self.assertRaisesRegex(ValueError, "holds"):
            self.export_review("held", self.root / "held.ndjson")
        self.assertFalse((self.root / "superseded.ndjson").exists())

    def test_new_observation_or_bulk_result_invalidates_old_review(self):
        self.capture(self.items)
        self.observe_missing("first")
        self.review("approved", "first")
        self.observe_missing("newer")
        with self.assertRaisesRegex(ValueError, "fresh observation"):
            self.export_review("approved", self.root / "stale.ndjson")
        self.review("new-approval", "newer")
        journal.record_bulk(self.db, "initial", "second-attempt", self.index, self.request, self.response)
        with self.assertRaisesRegex(ValueError, "newer bulk"):
            self.export_review("new-approval", self.root / "older-result.ndjson")
        with self.assertRaisesRegex(ValueError, "fresh observation"):
            self.review("too-early", "newer", attempt="second-attempt")
        self.observe_missing("after-second")
        self.review("new-result", "after-second", attempt="second-attempt")
        self.assertEqual(self.export_review("new-result", self.root / "current.ndjson")["documents"], 1)

    def test_observation_before_bulk_and_legacy_watermark_require_fresh_capture(self):
        self.observe_missing("before-failure")
        self.capture(self.items)
        with self.assertRaisesRegex(ValueError, "fresh observation"):
            self.review("old-observation", "before-failure")
        self.observe_missing("after-failure")
        with closing(journal.connect(self.db, write=True)) as db, db:
            db.execute("UPDATE observations SET bulk_watermark=NULL WHERE id='after-failure'")
        with self.assertRaisesRegex(ValueError, "fresh observation"):
            self.review("legacy-observation", "after-failure")
        with closing(journal.connect(self.db, write=False)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM bulk_reviews").fetchone()[0], 0)

    def test_confirmed_or_mismatched_source_never_releases_a_reviewed_retry(self):
        self.capture(self.items)
        for version in (1, 2):
            snapshot = self.root / "found.json"
            hits = [{"_id": key, "_index": self.index, "found": False} for key in self.ids]
            hits[2].update(found=True, _source=self.docs[self.ids[2]], _version=version)
            snapshot.write_text(json.dumps({"docs": hits}))
            label = "found-" + str(version)
            journal.observe(self.db, "initial", label, self.index, snapshot)
            with self.assertRaisesRegex(ValueError, "explicit absence"):
                self.review("no-retry-" + str(version), label)

    def test_review_export_excludes_a_concurrent_evidence_writer(self):
        self.capture(self.items)
        self.observe_missing("current")
        self.review("approved", "current")
        write = journal.write_payloads

        def concurrent_write(rows, output):
            with closing(sqlite3.connect(self.db, timeout=0)) as other:
                with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                    other.execute("BEGIN IMMEDIATE")
            return write(rows, output)

        with patch.object(journal, "write_payloads", side_effect=concurrent_write):
            self.assertEqual(self.export_review("approved", self.root / "current.ndjson")["documents"], 1)
        self.review("hold-after-export", "current", decision="hold")
        with self.assertRaisesRegex(ValueError, "later review"):
            self.export_review("approved", self.root / "revoked.ndjson")


if __name__ == "__main__":
    unittest.main()
