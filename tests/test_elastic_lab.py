"""Harness safety regressions, separate from the actual vendor integration run."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location(
    "elastic_lab", Path(__file__).resolve().parents[1] / "scripts/run_elastic_lab.py"
)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


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


if __name__ == "__main__":
    unittest.main()
