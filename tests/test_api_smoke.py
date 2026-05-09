import json
import re
import shutil
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
            fake_ai_server, fake_ai_thread, fake_ai_url = start_fake_openai_server()
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
                        "endpoint": f"{fake_ai_url}/v1",
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
                self.assertIn("eventIndex", live)
                self.assertIn("visitors", live)
                self.assertIn("agents", live)

                duplicate_incident = request(
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
                self.assertEqual(duplicate_incident["severity"], "high")
                event_index = request(base_url, "/api/v1/events/index", token="admin-token", method="GET")
                self.assertGreaterEqual(event_index["duplicatesCollapsed"], 1)
                self.assertGreaterEqual(event_index["priorityCounts"]["high"], 1)
                self.assertGreaterEqual(len(event_index["days"]), 1)
                indexed_login = next(item for item in event_index["items"] if item["asset"]["id"] == "/login")
                self.assertEqual(indexed_login["duplicateCount"], 2)
                self.assertEqual(indexed_login["priority"]["level"], "high")
                self.assertIn("username=admin", indexed_login["attackerInput"]["summary"])

                managed_summary = request(base_url, "/api/v1/managed-site/summary", token="ingest-token", method="GET")
                self.assertIn("consoleUrl", managed_summary)
                self.assertIn("managedEntryUrl", managed_summary)
                self.assertGreaterEqual(len(managed_summary["agents"]), 1)

                managed_entry_html = request_text(base_url, "/managed-entry", method="GET")
                self.assertIn("managed-entry.js", managed_entry_html)

                headers = response_headers(base_url, "/", method="GET")
                self.assertIn("Content-Security-Policy", headers)
                self.assertIn("frame-ancestors 'self'", headers["Content-Security-Policy"])
                self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
                self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")

                same_origin_headers = response_headers(
                    base_url,
                    "/api/v1/status",
                    method="GET",
                    headers={"Origin": base_url},
                )
                self.assertEqual(same_origin_headers.get("Access-Control-Allow-Origin"), base_url)
                blocked_origin_headers = response_headers(
                    base_url,
                    "/api/v1/status",
                    method="GET",
                    headers={"Origin": "https://evil.example"},
                )
                self.assertNotIn("Access-Control-Allow-Origin", blocked_origin_headers)

                managed_entry_js = request_text(base_url, "/static/managed-entry.js", method="GET")
                self.assertNotIn("URLSearchParams", managed_entry_js)
                self.assertIn("sessionStorage", managed_entry_js)

                mission_map = request(base_url, "/static/mission-map.json", method="GET")
                self.assertIn("nodes", mission_map)
                self.assertGreaterEqual(len(mission_map["nodes"]), 5)

                chat = request(
                    base_url,
                    "/api/v1/ai/chat",
                    token="admin-token",
                    body={"agentId": "agent_local", "message": "请报告访客和事件状态"},
                )
                self.assertTrue(chat["ok"])
                self.assertEqual(chat["reply"]["role"], "agent")
                self.assertEqual(chat["reply"]["metadata"]["source"], "connected-ai-model")
                self.assertEqual(chat["reply"]["metadata"]["provider"], "Local vLLM")
                self.assertTrue(chat["llmAvailable"])
                self.assertFalse(chat["fallbackUsed"])
                self.assertIn("FAKE_AI_CHAT_OK", chat["reply"]["message"])
                self.assertIn("provider", chat)
                history = request(base_url, "/api/v1/ai/chat?agentId=agent_local", token="admin-token", method="GET")
                self.assertGreaterEqual(len(history["items"]), 2)

                model_incident = request(
                    base_url,
                    "/api/v1/events/ingest",
                    token="ingest-token",
                    body={
                        "source": "app",
                        "category": "request",
                        "trustLabel": "low",
                        "severityHint": "high",
                        "actor": {"type": "ip", "id": "198.51.100.91", "ip": "198.51.100.91"},
                        "asset": {"kind": "site", "id": "/api/search"},
                        "payload": {"query": "<script>alert(1)</script>"},
                    },
                )
                self.assertEqual(model_incident["analysis"]["provider"], "Local vLLM")
                self.assertTrue(model_incident["analysis"]["llmAvailable"])
                self.assertFalse(model_incident["analysis"]["fallbackUsed"])
                self.assertIn("Fake model structured summary", model_incident["analysis"]["summary"])

                for provider_type in ("deepseek", "glm", "kimi"):
                    china_provider = request(
                        base_url,
                        "/api/v1/providers",
                        token="admin-token",
                        body={
                            "name": f"{provider_type} test provider",
                            "providerType": provider_type,
                            "endpoint": f"{fake_ai_url}/v1",
                            "model": f"{provider_type}-test-model",
                            "apiKeySecretRef": "",
                            "supportsStructuredOutput": True,
                            "supportsToolCalling": False,
                            "enabled": True,
                        },
                    )
                    self.assertTrue(china_provider["active"])
                    china_chat = request(
                        base_url,
                        "/api/v1/ai/chat",
                        token="admin-token",
                        body={"agentId": "agent_local", "message": f"{provider_type} status check"},
                    )
                    self.assertTrue(china_chat["llmAvailable"])
                    self.assertFalse(china_chat["fallbackUsed"])
                    self.assertEqual(china_chat["reply"]["metadata"]["provider"], f"{provider_type} test provider")

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
                fake_ai_server.shutdown()
                fake_ai_server.server_close()
                fake_ai_thread.join(timeout=5)
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class FakeOpenAIHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length).decode("utf-8")
        body = json.loads(raw or "{}")
        messages = body.get("messages") if isinstance(body.get("messages"), list) else []
        latest_content = str(messages[-1].get("content") if messages else "")
        if "\"event\"" in latest_content and "\"score\"" in latest_content:
            content = json.dumps(
                {
                    "verdict": "suspicious",
                    "confidence": 0.88,
                    "summary": "Fake model structured summary from OpenAI-compatible test server.",
                    "evidenceSignals": ["fake_model_signal"],
                    "recommendedActions": [{"actionId": "capture_evidence", "reason": "fake model request"}],
                    "requiresHumanApproval": True,
                }
            )
        else:
            content = "FAKE_AI_CHAT_OK: connected model received SentinelAI context and answered the operator."
        payload = {"choices": [{"message": {"content": content}}]}
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        return


def start_fake_openai_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeOpenAIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://{server.server_address[0]}:{server.server_address[1]}"


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


def response_headers(base_url, path, *, method="GET", token=None, body=None, headers=None):
    request_headers = {"Content-Type": "application/json"}
    request_headers.update(headers or {})
    data = None
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(base_url + path, data=data, headers=request_headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        return dict(response.headers.items())


def captcha_answer(question):
    left, right, multiplier = [int(item) for item in re.findall(r"\d+", question)]
    return str((left + right) * multiplier)


if __name__ == "__main__":
    unittest.main()
