import json
import re
import shutil
import threading
import unittest
import urllib.error
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

                auth_error = request_error(base_url, "/api/v1/incidents", method="GET")
                self.assertEqual(auth_error["code"], "AUTH_REQUIRED")
                self.assertIn("messageZh", auth_error)

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
                self.assertIn("agents", live)

                managed_summary = request(base_url, "/api/v1/managed-site/summary", token="ingest-token", method="GET")
                self.assertIn("consoleUrl", managed_summary)
                self.assertIn("managedEntryUrl", managed_summary)
                self.assertGreaterEqual(len(managed_summary["agents"]), 1)

                managed_entry_html = request_text(base_url, "/managed-entry", method="GET")
                self.assertIn("managed-entry.js", managed_entry_html)

                chat = request(
                    base_url,
                    "/api/v1/ai/chat",
                    token="admin-token",
                    body={"agentId": "agent_local", "message": "status please"},
                )
                self.assertTrue(chat["ok"])
                self.assertEqual(chat["reply"]["role"], "agent")
                self.assertEqual(chat["reply"]["metadata"]["source"], "connected-ai-model")
                self.assertIn("provider", chat)
                history = request(base_url, "/api/v1/ai/chat?agentId=agent_local", token="admin-token", method="GET")
                self.assertGreaterEqual(len(history["items"]), 2)

                visitor_body = {"ip": "203.0.113.77", "userAgent": "UnitTestScanner/1.0", "path": "/pricing", "method": "GET"}
                request(base_url, "/api/v1/visitors/record", token="ingest-token", body=visitor_body)
                request(base_url, "/api/v1/visitors/record", token="ingest-token", body=visitor_body)
                visitors = request(base_url, "/api/v1/visitors", token="admin-token", method="GET")["items"]
                pricing_records = [item for item in visitors if item["ip"] == "203.0.113.77" and item["path"] == "/pricing"]
                self.assertEqual(len(pricing_records), 1)
                self.assertEqual(pricing_records[0]["visitCount"], 2)

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


def request_error(base_url, path, *, method="POST", token=None, body=None):
    try:
        request(base_url, path, method=method, token=token, body=body)
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode("utf-8"))
        finally:
            exc.close()
    raise AssertionError("request unexpectedly succeeded")


def request_text(base_url, path, *, method="GET", token=None, body=None):
    headers = {"Content-Type": "application/json"}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        return response.read().decode("utf-8")


def captcha_answer(question):
    left, right, multiplier = [int(item) for item in re.findall(r"\d+", question)]
    return str((left + right) * multiplier)


if __name__ == "__main__":
    unittest.main()
