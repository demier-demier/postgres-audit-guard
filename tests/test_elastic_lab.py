"""Harness safety regressions, separate from the actual vendor integration run."""

import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "elastic_lab", Path(__file__).resolve().parents[1] / "scripts/run_elastic_lab.py"
)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)
import elastic_receipts as receipts


class HarnessSafety(unittest.TestCase):
    def test_http_redirect_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "redirects are forbidden"):
            lab.NoRedirects().redirect_request(None, None, 302, "redirect", {}, "https://example.invalid/")

    def test_shutdown_tolerates_exit_between_poll_and_signal(self):
        child = MagicMock(pid=123)
        child.poll.return_value = None
        with patch.object(lab.os, "killpg", side_effect=ProcessLookupError):
            lab.stop(child)
        child.wait.assert_called_once_with(timeout=30)

    def test_cleanup_attempts_every_child_and_closes_handles_after_error(self):
        first, second, handle = MagicMock(), MagicMock(), MagicMock()
        first.poll.return_value = second.poll.return_value = 0
        with patch.object(lab, "stop", side_effect=[OSError("synthetic"), None]) as stop:
            with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                lab.cleanup([first, second], [handle])
        self.assertEqual(stop.call_count, 2)
        self.assertIs(stop.call_args_list[1].args[0], first)
        handle.close.assert_called_once()

    def test_timestamp_equivalence_preserves_nanoseconds(self):
        base = {"@timestamp": "2026-01-02T03:04:05.123456789-03:00", "event": {"outcome": "unknown"}}
        utc = {"@timestamp": "2026-01-02T06:04:05.123456789Z", "event": {"outcome": "unknown"}}
        self.assertEqual(lab.normalized(base), lab.normalized(utc))
        utc["@timestamp"] = "2026-01-02T06:04:05.123456780Z"
        self.assertNotEqual(lab.normalized(base), lab.normalized(utc))
        self.assertEqual(base["@timestamp"], "2026-01-02T03:04:05.123456789-03:00")


class DeliveryJournal(unittest.TestCase):
    index = "synthetic-index"
    label = "capture"

    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.work = Path(temp.name)
        self.path = self.work / "journal.db"
        self.capture = self.work / "capture.json"
        self.ids = ["a" * 64, "b" * 64]
        # Seed a v1 journal to exercise migration of already-accepted rows.
        self.docs = {"@timestamp": "2026-02-01T12:00:00.000000001Z", "meta": {"ok": False}}
        self.payload = json.dumps(self.docs).encode() + b"\n"
        with sqlite3.connect(self.path) as db:
            db.executescript(receipts.SCHEMA)
            db.execute(f"PRAGMA application_id={receipts.APPLICATION_ID}")
            db.execute("PRAGMA user_version=1")
            db.execute("INSERT INTO batches VALUES ('initial', 'synthetic', 2, 0)")
            db.executemany("INSERT INTO documents VALUES (?, ?, ?, 'initial')",
                           [(key, self.payload, receipts.digest(self.payload)) for key in self.ids])
            db.executemany("INSERT INTO receipts VALUES ('initial', ?, ?, 'accepted', ?, NULL)",
                           [(ordinal, key, receipts.digest(self.payload)) for ordinal, key in enumerate(self.ids, 1)])
        self.found = {"_id": self.ids[0], "_index": self.index, "found": True,
                      "_version": 1, "_source": self.docs}
        self.missing = {"_id": self.ids[1], "_index": self.index, "found": False}

    def observe(self, *documents, label=None):
        self.capture.write_text(json.dumps({"docs": documents}))
        return receipts.observe(self.path, "initial", label or self.label, self.index, self.capture)

    def test_migration_retry_and_recovery_from_persisted_state(self):
        expected = self.observe(self.missing, self.found)
        self.assertEqual(expected["counts"], {"confirmed": 1, "missing": 1, "mismatch": 0})
        self.assertEqual(expected, self.observe(self.missing, self.found))
        with self.assertRaisesRegex(ValueError, "already binds"):
            self.observe(self.found, self.missing)
        with receipts.closing(receipts.connect(self.path, write=False)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
            out = self.work / "retry.ndjson"
            self.assertEqual(receipts.recover(db, self.label, out)["documents"], 1)
            self.assertEqual(out.read_bytes(), self.payload)
            with self.assertRaises(FileExistsError):
                receipts.recover(db, self.label, out)

    def test_mismatch_is_never_replayed_by_recovery(self):
        changed = dict(self.found, _source={**self.docs, "meta": {"ok": 0}})
        rewritten = dict(self.found, _id=self.ids[1], _version=2)
        result = self.observe(changed, rewritten)
        self.assertEqual(result["counts"], {"confirmed": 0, "missing": 0, "mismatch": 2})
        self.assertNotEqual(result["events"][0]["stored_source_sha256"],
                            result["events"][0]["expected_source_sha256"])
        self.assertEqual(result["events"][1]["stored_source_sha256"],
                         result["events"][1]["expected_source_sha256"])
        with receipts.closing(receipts.connect(self.path, write=False)) as db:
            self.assertEqual(receipts.recover(db, self.label, self.work / "empty.ndjson")["documents"], 0)

    def test_partial_and_ambiguous_responses_leave_no_observation(self):
        for response in [
            [self.found],
            [self.found, dict(self.missing, error={"type": "shard_failure"})],
            [self.found, dict(self.missing, _index="unexpected-index")],
            [self.found, self.found],
            [self.found, dict(self.missing, found=0)],
            [self.found, dict(self.missing, _id="c" * 64)],
            [self.found, dict(self.missing, found=True, _version=1)],
            [dict(self.found, _version=True), self.missing],
            [dict(self.found, _source={**self.docs, "other": float("nan")}), self.missing],
        ]:
            with self.subTest(response=response), self.assertRaises(ValueError):
                self.observe(*response)
        self.capture.write_bytes(b'{"docs":[],"docs":[]}')
        with self.assertRaisesRegex(ValueError, "ambiguous JSON"):
            receipts.observe(self.path, "initial", self.label, self.index, self.capture)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM documents").fetchone()[0], 2)

    def test_stale_snapshot_is_readable_but_cannot_emit_a_spool(self):
        old = self.observe(self.found, self.missing)
        self.observe(self.found, dict(self.found, _id=self.ids[1]), label="later")
        with receipts.closing(receipts.connect(self.path, write=False)) as db:
            self.assertEqual(receipts.delivery_receipt(db, self.label), old)
            out = self.work / "stale.ndjson"
            with self.assertRaisesRegex(ValueError, "latest recorded"):
                receipts.recover(db, self.label, out)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
