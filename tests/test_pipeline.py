import shutil
import unittest
import uuid
from pathlib import Path

from sentinelai_plugin.pipeline import process_event
from sentinelai_plugin.storage import Storage


class PipelineTests(unittest.TestCase):
    def test_process_event_stores_incident_and_redacts_payload(self):
        tmp = Path.cwd() / ".test-work" / f"pipeline-{uuid.uuid4().hex}"
        tmp.mkdir(parents=True, exist_ok=True)
        try:
            storage = Storage(tmp / "sentinelai.sqlite3")
            storage.init()
            storage.ensure_defaults()

            incident = process_event(
                storage,
                {
                    "source": "app",
                    "category": "request",
                    "trustLabel": "low",
                    "severityHint": "medium",
                    "actor": {"type": "ip", "id": "198.51.100.23", "ip": "198.51.100.23"},
                    "asset": {"kind": "site", "id": "/admin"},
                    "payload": {"Authorization": "Bearer abcdefghijklmnopqrstuvwxyz", "body": "<script>alert(1)</script>"},
                },
                actor="unit-test",
            )

            self.assertTrue(incident["id"].startswith("inc_"))
            self.assertIn("actionRuns", incident)
            payload = incident["event"]["redactedPayload"]
            self.assertEqual(payload["Authorization"], "[REDACTED]")
            self.assertLess(incident["trustScore"], 90)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
