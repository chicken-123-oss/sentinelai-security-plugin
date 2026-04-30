import json
import re
import shutil
import threading
import unittest
import urllib.request
import uuid
from pathlib import Path

from sentinelai_plugin.config import Settings
from sentinelai_plugin.server import create_http_server


class ApiSmokeTests(unittest.TestCase):
    def test_login_ingest_list_and_execute_capture_evidence(self):
        tmp = Path.cwd() / ".test-work" / f"api-{uuid.uuid4().hex}"
        tmp.mkdir(parents=True, exist_ok=True)
        try:
            settings = Settings(
                host="127.0.0.1",
                port=0,
                db_path=tmp / "sentinelai.sqlite3",
                data_dir=tmp,
                admin_password="pw",
                admin_token="admin-token",
                ingest_token="ingest-token",
            )
            server = create_http_server(settings, demo=False)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base_url = f"http://{server.server_address[0]}:{server.server_address[1]}"
            try:
                captcha = request(base_url, "/api/v1/auth/captcha", method="GET")
                login = request(
                    base_url,
                    "/api/v1/auth/login",
                    body={
                        "email": "admin@example.com",
                        "password": "pw",
                        "captchaId": captcha["challengeId"],
                        "captchaAnswer": captcha_answer(captcha["question"]),
                    },
                )
                self.assertEqual(login["token"], "admin-token")

                incident = request(
                    base_url,
                    "/api/v1/events/ingest",
                    token="ingest-token",
                    body={
                        "source": "nginx",
                        "category": "request",
                        "trustLabel": "low",
                        "severityHint": "high",
                        "actor": {"type": "ip", "id": "203.0.113.9", "ip": "203.0.113.9"},
                        "asset": {"kind": "site", "id": "/login"},
                        "payload": {"body": "username=admin' OR '1'='1"},
                    },
                )
                self.assertEqual(incident["severity"], "high")

                listed = request(base_url, "/api/v1/incidents", token="admin-token", method="GET")
                self.assertEqual(len(listed["items"]), 1)

                capture = next(run for run in incident["actionRuns"] if run["actionId"] == "capture_evidence")
                executed = request(
                    base_url,
                    f"/api/v1/action-runs/{capture['id']}/execute",
                    token="admin-token",
                    body={},
                )
                self.assertEqual(executed["status"], "completed")
                self.assertTrue((tmp / "evidence" / f"{incident['id']}.json").exists())

                provider = request(
                    base_url,
                    "/api/v1/providers",
                    token="admin-token",
                    body={
                        "name": "Local vLLM",
                        "providerType": "openai_compatible",
                        "endpoint": "http://127.0.0.1:9999/v1",
                        "model": "security-model",
                        "apiKeySecretRef": "SENTINELAI_TEST_KEY",
                        "supportsStructuredOutput": True,
                        "supportsToolCalling": False,
                        "enabled": True,
                    },
                )
                self.assertTrue(provider["active"])

                live = request(base_url, "/api/v1/monitor/live", token="admin-token", method="GET")
                self.assertGreaterEqual(len(live["events"]), 1)
                self.assertIn("visitors", live)

                changed = request(
                    base_url,
                    "/api/v1/auth/change-password",
                    token="admin-token",
                    body={"currentPassword": "pw", "newPassword": "newpass1234"},
                )
                self.assertTrue(changed["ok"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def request(base_url, path, *, method="POST", token=None, body=None):
    headers = {"Content-Type": "application/json"}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def captcha_answer(question):
    left, right, multiplier = [int(item) for item in re.findall(r"\d+", question)]
    return str((left + right) * multiplier)


if __name__ == "__main__":
    unittest.main()
