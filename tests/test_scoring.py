import unittest

from sentinelai_plugin.models import normalize_event
from sentinelai_plugin.scoring import score_event


class ScoringTests(unittest.TestCase):
    def test_sql_injection_event_reduces_trust_and_recommends_actions(self):
        event = normalize_event(
            {
                "source": "nginx",
                "category": "request",
                "trustLabel": "low",
                "severityHint": "high",
                "actor": {"type": "ip", "id": "203.0.113.10", "ip": "203.0.113.10"},
                "asset": {"kind": "site", "id": "/login"},
                "redactedPayload": {"body": "username=admin' OR '1'='1"},
            }
        )

        score = score_event(event).to_dict()

        self.assertLess(score["trustScore"], 60)
        self.assertEqual(score["severity"], "high")
        self.assertIn("sql_injection", score["signals"])
        self.assertIn("capture_evidence", score["recommendedActions"])
        self.assertIn("block_ip", score["recommendedActions"])

    def test_benign_event_remains_observable(self):
        event = normalize_event(
            {
                "source": "app",
                "category": "request",
                "trustLabel": "high",
                "severityHint": "info",
                "actor": {"type": "ip", "id": "192.0.2.1", "ip": "192.0.2.1"},
                "asset": {"kind": "site", "id": "/"},
                "redactedPayload": {"path": "/", "status": 200},
            }
        )

        score = score_event(event).to_dict()

        self.assertGreaterEqual(score["trustScore"], 90)
        self.assertEqual(score["statusHint"], "observe")
        self.assertEqual(score["recommendedActions"], [])


if __name__ == "__main__":
    unittest.main()

