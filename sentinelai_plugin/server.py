from __future__ import annotations

import argparse
import json
import mimetypes
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__
from .actions import execute_action
from .auth import validate_new_password
from .config import Settings
from .llm import build_adapter
from .models import (
    ROLE_AGENT,
    ROLE_AUDITOR,
    ROLE_SECURITY_ADMIN,
    ROLE_TENANT_OWNER,
    make_id,
    normalize_provider,
)
from .pipeline import process_event
from .policy import can_execute_action, role_can_configure, role_can_operate, role_can_view
from .sample_data import seed_demo
from .storage import Storage


@dataclass(frozen=True)
class AuthContext:
    actor: str
    role: str


class ApiError(Exception):
    def __init__(self, status: int, message: str, code: str | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code or _error_code(message)


class SecurityApp:
    def __init__(self, settings: Settings, storage: Storage):
        self.settings = settings
        self.storage = storage

    def dispatch(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(handler.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        try:
            if _should_record_visitor(path, handler.command):
                try:
                    self.storage.record_visitor(
                        handler.client_address[0],
                        handler.headers.get("User-Agent", "unknown"),
                        path,
                        handler.command,
                    )
                except Exception:
                    pass
            if handler.command == "GET":
                self._get(handler, path, query)
            elif handler.command == "POST":
                self._post(handler, path)
            elif handler.command == "PATCH":
                self._patch(handler, path)
            elif handler.command == "OPTIONS":
                _send_json(handler, 204, {})
            else:
                raise ApiError(405, "method not allowed")
        except ApiError as exc:
            _send_error(handler, exc.status, exc.message, exc.code)
        except json.JSONDecodeError:
            _send_error(handler, 400, "invalid JSON body", "INVALID_JSON")
        except Exception as exc:  # pragma: no cover - final guard for API resilience.
            _send_error(handler, 500, "internal server error", "INTERNAL_ERROR", details=str(exc))

    def _get(self, handler: BaseHTTPRequestHandler, path: str, query: dict[str, list[str]]) -> None:
        if path == "/":
            _send_static(handler, "index.html")
            return
        if path == "/managed-entry":
            _send_static(handler, "managed-entry.html")
            return
        if path.startswith("/static/"):
            _send_static(handler, path.removeprefix("/static/"))
            return
        if path == "/api/v1/status":
            _send_json(handler, 200, self._status_payload())
            return
        if path == "/api/v1/auth/captcha":
            _send_json(handler, 200, self.storage.create_captcha())
            return
        if path == "/api/v1/monitor/live":
            self._require_view(handler)
            _send_json(
                handler,
                200,
                {
                    "status": self._status_payload(),
                    "activeProvider": self.storage.get_active_provider(),
                    "incidents": self.storage.list_incidents(limit=12),
                    "events": self.storage.list_events(limit=24),
                    "eventIndex": self.storage.list_event_index(limit=80),
                    "attackSummary": self.storage.attack_category_summary(),
                    "visitors": self.storage.list_visitors(limit=24),
                    "agents": self.storage.list_agents(),
                    "audit": self.storage.list_audit_logs(limit=12),
                },
            )
            return
        if path == "/api/v1/incidents":
            self._require_view(handler)
            limit = _int_query(query, "limit", 50)
            _send_json(handler, 200, {"items": self.storage.list_incidents(limit=limit)})
            return
        if path.startswith("/api/v1/incidents/"):
            self._require_view(handler)
            incident_id = path.split("/")[-1]
            incident = self.storage.get_incident_bundle(incident_id)
            if incident is None:
                raise ApiError(404, "incident not found")
            _send_json(handler, 200, incident)
            return
        if path == "/api/v1/audit-logs":
            self._require_view(handler)
            limit = _int_query(query, "limit", 100)
            _send_json(handler, 200, {"items": self.storage.list_audit_logs(limit=limit)})
            return
        if path == "/api/v1/providers":
            self._require_view(handler)
            _send_json(handler, 200, {"items": self.storage.list_providers()})
            return
        if path == "/api/v1/agents":
            self._require_view(handler)
            _send_json(handler, 200, {"items": self.storage.list_agents()})
            return
        if path in {"/api/v1/agent/chat", "/api/v1/ai/chat"}:
            self._require_view(handler)
            agent_id = _str_query(query, "agentId", self._default_agent_id())
            _send_json(handler, 200, {"agentId": agent_id, "items": self.storage.list_agent_messages(agent_id, limit=80)})
            return
        if path in {"/api/v1/managed-site/summary", "/api/v1/managed-site/entry"}:
            self._require_auth(handler, allow_ingest=True)
            _send_json(handler, 200, self._managed_site_summary(handler))
            return
        if path == "/api/v1/events":
            self._require_view(handler)
            limit = _int_query(query, "limit", 80)
            _send_json(handler, 200, {"items": self.storage.list_events(limit=limit)})
            return
        if path == "/api/v1/events/index":
            self._require_view(handler)
            limit = _int_query(query, "limit", 160)
            _send_json(handler, 200, self.storage.list_event_index(limit=limit))
            return
        if path == "/api/v1/visitors":
            self._require_view(handler)
            limit = _int_query(query, "limit", 100)
            _send_json(handler, 200, {"items": self.storage.list_visitors(limit=limit)})
            return
        raise ApiError(404, "route not found")

    def _post(self, handler: BaseHTTPRequestHandler, path: str) -> None:
        if path == "/api/v1/auth/login":
            body = _read_json(handler)
            password = str(body.get("password") or "")
            email = str(body.get("email") or self.settings.admin_email)
            captcha_id = str(body.get("captchaId") or "")
            captcha_answer = str(body.get("captchaAnswer") or "")
            if not self.storage.verify_captcha(captcha_id, captcha_answer):
                raise ApiError(401, "captcha verification failed")
            if not self.storage.verify_admin(email, password):
                raise ApiError(401, "invalid credentials")
            self.storage.add_audit(email, "auth.login", "session", {"role": ROLE_TENANT_OWNER})
            _send_json(handler, 200, {"token": self.settings.admin_token, "role": ROLE_TENANT_OWNER, "email": email})
            return

        if path == "/api/v1/auth/change-password":
            ctx = self._require_auth(handler)
            if ctx.role != ROLE_TENANT_OWNER:
                raise ApiError(403, "only TENANT_OWNER can change the owner password")
            body = _read_json(handler)
            current_password = str(body.get("currentPassword") or "")
            new_password = str(body.get("newPassword") or "")
            valid, message = validate_new_password(new_password)
            if not valid:
                raise ApiError(400, message)
            if not self.storage.change_admin_password(ctx.actor, current_password, new_password):
                raise ApiError(401, "current password is invalid")
            self.storage.add_audit(ctx.actor, "auth.password_changed", "admin_auth", {})
            _send_json(handler, 200, {"ok": True, "message": "password changed"})
            return

        if path == "/api/v1/events/ingest":
            ctx = self._require_auth(handler, allow_ingest=True)
            incident = process_event(self.storage, _read_json(handler), actor=ctx.actor)
            _send_json(handler, 201, incident)
            return

        if path == "/api/v1/visitors/record":
            ctx = self._require_auth(handler, allow_ingest=True)
            body = _read_json(handler)
            ip = str(body.get("ip") or handler.client_address[0])
            user_agent = str(body.get("userAgent") or body.get("user_agent") or handler.headers.get("User-Agent", "unknown"))
            visit_path = str(body.get("path") or "/")
            method = str(body.get("method") or "GET")
            self.storage.record_visitor(ip, user_agent, visit_path, method)
            self.storage.add_audit(ctx.actor, "visitor.recorded", ip, {"path": visit_path, "method": method})
            _send_json(handler, 201, {"ok": True, "message": "visitor record accepted", "messageZh": "访客记录已接收；重复访问信息会更新计数，不会重复插入。"})
            return

        if path == "/api/v1/sites":
            ctx = self._require_auth(handler)
            if not role_can_configure(ctx.role):
                raise ApiError(403, "only TENANT_OWNER can create sites")
            body = _read_json(handler)
            site_id = str(body.get("id") or make_id("site"))
            site = self.storage.upsert_site(site_id, str(body.get("name") or site_id))
            self.storage.add_audit(ctx.actor, "site.upserted", site_id, site)
            _send_json(handler, 201, site)
            return

        if path == "/api/v1/agents/register":
            ctx = self._require_auth(handler, allow_ingest=True)
            body = _read_json(handler)
            agent_id = str(body.get("id") or make_id("agent"))
            agent = self.storage.register_agent(
                agent_id,
                str(body.get("siteId") or "site_default"),
                str(body.get("name") or agent_id),
                body.get("metadata") if isinstance(body.get("metadata"), dict) else {},
            )
            self.storage.add_audit(ctx.actor, "agent.registered", agent_id, agent)
            _send_json(handler, 201, agent)
            return

        if path == "/api/v1/agents/check-in":
            ctx = self._require_auth(handler, allow_ingest=True)
            body = _read_json(handler)
            agent_id = str(body.get("id") or body.get("agentId") or "agent_local")
            agent = self.storage.check_in_agent(
                agent_id,
                str(body.get("status") or "healthy"),
                str(body.get("policyVersion") or "bundle-dev"),
                body.get("metadata") if isinstance(body.get("metadata"), dict) else {},
            )
            self.storage.add_audit(ctx.actor, "agent.check_in", agent_id, agent)
            _send_json(handler, 200, agent)
            return

        if path in {"/api/v1/agent/chat", "/api/v1/ai/chat"}:
            ctx = self._require_auth(handler)
            if not role_can_operate(ctx.role):
                raise ApiError(403, "role cannot chat with connected AI")
            body = _read_json(handler)
            message = str(body.get("message") or "").strip()
            if not message:
                raise ApiError(400, "message is required")
            agent_id = str(body.get("agentId") or self._default_agent_id())
            user_message = self.storage.add_agent_message(agent_id, "user", message, {"actor": ctx.actor})
            reply = self._build_ai_chat_reply(agent_id, message)
            agent_message = self.storage.add_agent_message(agent_id, "agent", reply["content"], reply["metadata"])
            self.storage.add_audit(ctx.actor, "agent.chat", agent_id, {"messageId": user_message["id"], "replyId": agent_message["id"]})
            _send_json(
                handler,
                200,
                {
                    "ok": True,
                    "agentId": agent_id,
                    "message": user_message,
                    "reply": agent_message,
                    "provider": reply["metadata"].get("provider"),
                    "llmAvailable": reply["metadata"].get("llmAvailable"),
                    "fallbackUsed": reply["metadata"].get("fallbackUsed"),
                    "items": self.storage.list_agent_messages(agent_id, limit=80),
                },
            )
            return

        if path == "/api/v1/providers":
            ctx = self._require_auth(handler)
            if not role_can_configure(ctx.role):
                raise ApiError(403, "only TENANT_OWNER can modify providers")
            provider = self.storage.create_provider(normalize_provider(_read_json(handler)))
            self.storage.add_audit(ctx.actor, "provider.upserted", provider["id"], {"providerType": provider["providerType"]})
            _send_json(handler, 201, provider)
            return

        if path.startswith("/api/v1/providers/") and path.endswith("/activate"):
            ctx = self._require_auth(handler)
            if not role_can_configure(ctx.role):
                raise ApiError(403, "only TENANT_OWNER can activate providers")
            provider_id = path.split("/")[-2]
            provider = self.storage.activate_provider(provider_id)
            if provider is None:
                raise ApiError(404, "provider not found")
            self.storage.add_audit(ctx.actor, "provider.activated", provider_id, {"providerType": provider["providerType"]})
            _send_json(handler, 200, provider)
            return

        if path.startswith("/api/v1/incidents/") and path.endswith("/approve"):
            ctx = self._require_auth(handler)
            if not role_can_operate(ctx.role):
                raise ApiError(403, "role cannot approve incidents")
            incident_id = path.split("/")[-2]
            if self.storage.get_incident_bundle(incident_id) is None:
                raise ApiError(404, "incident not found")
            self.storage.approve_incident(incident_id, ctx.actor)
            _send_json(handler, 200, self.storage.get_incident_bundle(incident_id))
            return

        if path.startswith("/api/v1/incidents/") and path.endswith("/reject"):
            ctx = self._require_auth(handler)
            if not role_can_operate(ctx.role):
                raise ApiError(403, "role cannot reject incidents")
            incident_id = path.split("/")[-2]
            if self.storage.get_incident_bundle(incident_id) is None:
                raise ApiError(404, "incident not found")
            body = _read_json(handler)
            self.storage.reject_incident(incident_id, ctx.actor, str(body.get("reason") or ""))
            _send_json(handler, 200, self.storage.get_incident_bundle(incident_id))
            return

        if path.startswith("/api/v1/action-runs/") and path.endswith("/execute"):
            ctx = self._require_auth(handler)
            action_run_id = path.split("/")[-2]
            action_run = self.storage.get_action_run(action_run_id)
            if action_run is None:
                raise ApiError(404, "action run not found")
            allowed, reason = can_execute_action(action_run, ctx.role)
            if not allowed:
                raise ApiError(409, reason)
            incident = self.storage.get_incident_bundle(action_run["incidentId"])
            if incident is None:
                raise ApiError(404, "incident not found")
            result = execute_action(
                action_run["actionId"],
                action_run["parameters"],
                incident,
                self.settings.data_dir,
                allow_system_actions=self.settings.allow_system_actions,
            )
            self.storage.update_action_run_result(action_run_id, result)
            self.storage.add_audit(ctx.actor, "action.execute", action_run_id, result)
            _send_json(handler, 200, self.storage.get_action_run(action_run_id))
            return

        raise ApiError(404, "route not found")

    def _patch(self, handler: BaseHTTPRequestHandler, path: str) -> None:
        if path.startswith("/api/v1/providers/"):
            ctx = self._require_auth(handler)
            if not role_can_configure(ctx.role):
                raise ApiError(403, "only TENANT_OWNER can modify providers")
            provider_id = path.split("/")[-1]
            body = _read_json(handler)
            body["id"] = provider_id
            provider = self.storage.create_provider(normalize_provider(body))
            self.storage.add_audit(ctx.actor, "provider.updated", provider_id, {"providerType": provider["providerType"]})
            _send_json(handler, 200, provider)
            return
        raise ApiError(404, "route not found")

    def _require_view(self, handler: BaseHTTPRequestHandler) -> AuthContext:
        ctx = self._require_auth(handler)
        if not role_can_view(ctx.role):
            raise ApiError(403, "role cannot view this resource")
        return ctx

    def _require_auth(self, handler: BaseHTTPRequestHandler, *, allow_ingest: bool = False) -> AuthContext:
        auth = handler.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer").strip()
        if token == self.settings.admin_token:
            return AuthContext(self.settings.admin_email, ROLE_TENANT_OWNER)
        if token == self.settings.auditor_token:
            return AuthContext("auditor@example.com", ROLE_AUDITOR)
        if allow_ingest and token == self.settings.ingest_token:
            return AuthContext("host-agent", ROLE_AGENT)
        raise ApiError(401, "missing or invalid bearer token")

    def _status_payload(self) -> dict[str, Any]:
        return {
            "ok": True,
            "version": __version__,
            "mode": "offline-safe",
            "counts": self.storage.counts(),
            "actionMode": "local-enabled" if self.settings.allow_system_actions else "dry-run-for-high-impact",
            "captcha": "math-choice-nonce",
            "languages": ["en", "zh-CN"],
        }

    def _default_agent_id(self) -> str:
        agents = self.storage.list_agents()
        return str(agents[0]["id"]) if agents else "agent_local"

    def _managed_site_summary(self, handler: BaseHTTPRequestHandler) -> dict[str, Any]:
        origin = _request_origin(handler)
        active_provider = self.storage.get_active_provider()
        return {
            "ok": True,
            "generatedAt": self.storage.current_time(),
            "status": self._status_payload(),
            "activeProvider": active_provider,
            "incidents": self.storage.list_incidents(limit=5),
            "visitors": self.storage.list_visitors(limit=5),
            "agents": self.storage.list_agents(),
            "recentAudit": self.storage.list_audit_logs(limit=5),
            "consoleUrl": f"{origin}/",
            "managedEntryUrl": f"{origin}/managed-entry",
            "redirectButton": {
                "label": "Open SentinelAI Console",
                "labelZh": "打开 SentinelAI 控制台",
                "url": f"{origin}/",
            },
        }

    def _build_ai_chat_reply(self, agent_id: str, message: str) -> dict[str, Any]:
        agents = self.storage.list_agents()
        agent = next((item for item in agents if item["id"] == agent_id), None)
        counts = self.storage.counts()
        incidents = self.storage.list_incidents(limit=3)
        visitors = self.storage.list_visitors(limit=3)
        active_provider = self.storage.get_active_provider() or {}
        prior_messages = self.storage.list_agent_messages(agent_id, limit=12)
        chat_messages = [
            {"role": "assistant" if item["role"] == "agent" else item["role"], "content": item["message"]}
            for item in prior_messages
        ]
        if not chat_messages or chat_messages[-1]["role"] != "user" or chat_messages[-1]["content"] != message:
            chat_messages.append({"role": "user", "content": message})
        context = {
            "counts": counts,
            "activeProvider": active_provider,
            "agent": agent,
            "incidents": incidents,
            "visitors": visitors,
        }
        result = build_adapter(active_provider).chat(chat_messages, context)
        metadata = {
            "source": "connected-ai-model",
            "provider": result.get("provider"),
            "llmAvailable": result.get("llmAvailable"),
            "fallbackUsed": result.get("fallbackUsed"),
        }
        if result.get("fallbackReason"):
            metadata["fallbackReason"] = result["fallbackReason"]
        return {"content": str(result.get("content") or ""), "metadata": metadata}


class SentinelRequestHandler(BaseHTTPRequestHandler):
    server_version = f"SentinelAI/{__version__}"

    def do_GET(self) -> None:
        self.server.app.dispatch(self)  # type: ignore[attr-defined]

    def do_POST(self) -> None:
        self.server.app.dispatch(self)  # type: ignore[attr-defined]

    def do_PATCH(self) -> None:
        self.server.app.dispatch(self)  # type: ignore[attr-defined]

    def do_OPTIONS(self) -> None:
        self.server.app.dispatch(self)  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return


class SentinelHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address: tuple[str, int], app: SecurityApp):
        super().__init__(server_address, SentinelRequestHandler)
        self.app = app


def create_http_server(settings: Settings, *, demo: bool = False) -> SentinelHTTPServer:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    storage = Storage(settings.db_path)
    storage.init()
    storage.ensure_defaults(settings.admin_email, settings.admin_password)
    if demo:
        seed_demo(storage)
    app = SecurityApp(settings, storage)
    return SentinelHTTPServer((settings.host, settings.port), app)


def run_server(settings: Settings, *, demo: bool = False) -> None:
    server = create_http_server(settings, demo=demo)
    host, port = server.server_address
    print(f"SentinelAI Security Plugin running at http://{host}:{port}")
    print(f"Login: {settings.admin_email} / {settings.admin_password}")
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the SentinelAI Security Plugin server.")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--db", default=None, help="SQLite database path")
    parser.add_argument("--data-dir", default=None, help="Writable data directory")
    parser.add_argument("--demo", action="store_true", help="Seed demo incidents on first launch")
    args = parser.parse_args(argv)
    settings = Settings.from_env(host=args.host, port=args.port, db_path=args.db, data_dir=args.data_dir)
    run_server(settings, demo=args.demo)
    return 0


def _read_json(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if length <= 0:
        return {}
    body = handler.rfile.read(length).decode("utf-8")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ApiError(400, "JSON body must be an object")
    return data


def _send_json(handler: BaseHTTPRequestHandler, status: int, body: dict[str, Any]) -> None:
    data = b"" if status == 204 else json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    _send_security_headers(handler, cache_control="no-store")
    _send_cors_headers(handler)
    handler.end_headers()
    if status != 204:
        handler.wfile.write(data)


def _send_error(handler: BaseHTTPRequestHandler, status: int, message: str, code: str, details: str | None = None) -> None:
    zh = _ERROR_ZH.get(code, _ERROR_ZH["UNKNOWN_ERROR"])
    body: dict[str, Any] = {
        "ok": False,
        "code": code,
        "error": message,
        "messageZh": zh["message"],
        "detailsZh": zh["details"],
        "hintZh": zh["hint"],
    }
    if details:
        body["details"] = details
    _send_json(handler, status, body)


def _send_static(handler: BaseHTTPRequestHandler, relative_path: str) -> None:
    safe_name = Path(relative_path).name
    if safe_name not in {"index.html", "app.js", "styles.css", "managed-entry.html", "managed-entry.js", "mission-map.json"}:
        raise ApiError(404, "static file not found")
    static_dir = Path(__file__).with_name("static")
    file_path = static_dir / safe_name
    if not file_path.exists():
        raise ApiError(404, "static file not found")
    data = file_path.read_bytes()
    content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    _send_security_headers(handler, cache_control="no-store")
    handler.end_headers()
    handler.wfile.write(data)


def _send_security_headers(handler: BaseHTTPRequestHandler, *, cache_control: str) -> None:
    app = getattr(handler.server, "app", None)  # type: ignore[attr-defined]
    settings = getattr(app, "settings", None)
    frame_ancestors = str(getattr(settings, "frame_ancestors", "'self'") or "'self'")
    csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        f"frame-ancestors {frame_ancestors}"
    )
    handler.send_header("Content-Security-Policy", csp)
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Referrer-Policy", "no-referrer")
    handler.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    handler.send_header("Cross-Origin-Opener-Policy", "same-origin")
    if frame_ancestors == "'self'":
        handler.send_header("X-Frame-Options", "SAMEORIGIN")
    elif frame_ancestors == "'none'":
        handler.send_header("X-Frame-Options", "DENY")
    handler.send_header("Cache-Control", cache_control)


def _send_cors_headers(handler: BaseHTTPRequestHandler) -> None:
    origin = handler.headers.get("Origin", "")
    if not origin:
        return
    handler.send_header("Vary", "Origin")
    if not _origin_allowed(handler, origin):
        return
    handler.send_header("Access-Control-Allow-Origin", origin)
    handler.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")


def _origin_allowed(handler: BaseHTTPRequestHandler, origin: str) -> bool:
    app = getattr(handler.server, "app", None)  # type: ignore[attr-defined]
    settings = getattr(app, "settings", None)
    allowed = set(getattr(settings, "allowed_origins", ()) or ())
    allowed.add(_request_origin(handler))
    return origin in allowed


def _int_query(query: dict[str, list[str]], key: str, default: int) -> int:
    try:
        return int(query.get(key, [str(default)])[0])
    except (TypeError, ValueError):
        return default


def _str_query(query: dict[str, list[str]], key: str, default: str) -> str:
    value = query.get(key, [default])[0]
    return str(value or default)


def _request_origin(handler: BaseHTTPRequestHandler) -> str:
    forwarded_proto = handler.headers.get("X-Forwarded-Proto", "").split(",")[0].strip()
    scheme = forwarded_proto or "http"
    host = handler.headers.get("Host")
    if not host:
        server_host, server_port = handler.server.server_address  # type: ignore[attr-defined]
        host = f"{server_host}:{server_port}"
    return f"{scheme}://{host}"


def _contains_cjk(value: str) -> bool:
    return any("\u4e00" <= char <= "\u9fff" for char in value)


def _should_record_visitor(path: str, method: str) -> bool:
    if path.startswith("/static/"):
        return False
    if method == "OPTIONS":
        return False
    # Dashboard polling and API list endpoints are internal reads, not new visitor information.
    ignored_prefixes = (
        "/api/v1/status",
        "/api/v1/auth/captcha",
        "/api/v1/monitor/live",
        "/api/v1/incidents",
        "/api/v1/events",
        "/api/v1/visitors",
        "/api/v1/managed-site",
        "/api/v1/agent/chat",
        "/api/v1/ai/chat",
        "/api/v1/audit-logs",
        "/api/v1/providers",
        "/api/v1/agents",
        "/api/v1/action-runs",
    )
    return path != "/managed-entry" and not any(path.startswith(prefix) for prefix in ignored_prefixes)


def _error_code(message: str) -> str:
    return {
        "captcha verification failed": "CAPTCHA_FAILED",
        "invalid credentials": "INVALID_CREDENTIALS",
        "missing or invalid bearer token": "AUTH_REQUIRED",
        "invalid JSON body": "INVALID_JSON",
        "route not found": "ROUTE_NOT_FOUND",
        "method not allowed": "METHOD_NOT_ALLOWED",
        "incident not found": "INCIDENT_NOT_FOUND",
        "provider not found": "PROVIDER_NOT_FOUND",
        "action run not found": "ACTION_RUN_NOT_FOUND",
        "current password is invalid": "CURRENT_PASSWORD_INVALID",
        "message is required": "MESSAGE_REQUIRED",
        "role cannot chat with connected AI": "AGENT_CHAT_FORBIDDEN",
    }.get(message, "UNKNOWN_ERROR")


_ERROR_ZH: dict[str, dict[str, str]] = {
    "CAPTCHA_FAILED": {
        "message": "验证码校验失败。",
        "details": "验证码可能不存在、已过期、答案错误，或者连续错误次数过多后已被作废。",
        "hint": "请刷新验证码，重新选择正确答案后再提交登录请求。",
    },
    "INVALID_CREDENTIALS": {
        "message": "登录失败：邮箱或密码不正确。",
        "details": "系统已完成验证码校验，但管理员账号凭据没有通过校验。",
        "hint": "请确认管理员邮箱和密码；如果刚修改过密码，请使用新密码重新登录。",
    },
    "AUTH_REQUIRED": {
        "message": "认证失败：缺少或无效的 Bearer Token。",
        "details": "该接口需要在请求头中提供 Authorization: Bearer <token>。当前令牌缺失、拼写错误、已替换，或使用了不允许访问该接口的令牌。",
        "hint": "登录后使用返回的管理员 token；采集端接口请使用 SENTINELAI_INGEST_TOKEN。",
    },
    "INVALID_JSON": {
        "message": "请求体不是有效的 JSON。",
        "details": "服务端无法解析请求体，常见原因包括引号不匹配、尾随逗号、编码错误，或 Content-Type 与实际内容不一致。",
        "hint": "请设置 Content-Type: application/json，并用 JSON 校验工具检查请求体。",
    },
    "ROUTE_NOT_FOUND": {
        "message": "接口路径不存在。",
        "details": "当前 URL 没有匹配到 SentinelAI 已注册的 API 路由。",
        "hint": "请核对 API 前缀 /api/v1、HTTP 方法以及路径参数。",
    },
    "METHOD_NOT_ALLOWED": {
        "message": "HTTP 方法不被允许。",
        "details": "该路径存在，但不接受当前使用的 GET、POST、PATCH 或其他方法。",
        "hint": "请参考 USAGE.md 中的接口说明，改用对应的 HTTP 方法。",
    },
    "INCIDENT_NOT_FOUND": {
        "message": "未找到指定事件。",
        "details": "incidentId 不存在，或事件数据已被更换到其他数据库路径。",
        "hint": "先调用 GET /api/v1/incidents 获取最新 incidentId。",
    },
    "PROVIDER_NOT_FOUND": {
        "message": "未找到指定模型供应商配置。",
        "details": "providerId 不存在，无法激活或更新该模型配置。",
        "hint": "先调用 GET /api/v1/providers 获取可用 providerId，或重新创建模型配置。",
    },
    "ACTION_RUN_NOT_FOUND": {
        "message": "未找到指定动作执行记录。",
        "details": "actionRunId 不存在，或该动作不属于当前数据库中的事件。",
        "hint": "打开事件详情，使用 actionRuns 数组中的 id 发起执行请求。",
    },
    "CURRENT_PASSWORD_INVALID": {
        "message": "当前密码不正确，无法修改密码。",
        "details": "为了保护最高管理员账号，修改密码前必须验证当前密码。",
        "hint": "请输入当前正在使用的管理员密码；成功修改后需要使用新密码重新登录。",
    },
    "MESSAGE_REQUIRED": {
        "message": "消息内容不能为空。",
        "details": "代理对话接口已经收到请求，但请求体中缺少 message 字段，或 message 只有空白字符。",
        "hint": "请使用 JSON 对象提交，例如 {\"agentId\":\"agent_local\",\"message\":\"请汇报当前状态\"}。",
    },
    "AGENT_CHAT_FORBIDDEN": {
        "message": "当前角色不能与连接 AI 对话。",
        "details": "连接 AI 对话会读取运行状态并写入会话记录，因此只允许 TENANT_OWNER 或 SECURITY_ADMIN 使用。",
        "hint": "请使用管理员账号登录后获取的 Bearer Token 调用该接口，审计员账号只能查看已有记录。",
    },
    "INTERNAL_ERROR": {
        "message": "服务端内部错误。",
        "details": "请求已到达服务端，但处理过程中发生未预期异常。",
        "hint": "请查看 server.err.log，并确认数据库路径、写入权限和请求参数是否正确。",
    },
    "UNKNOWN_ERROR": {
        "message": "请求处理失败。",
        "details": "服务端返回了错误，但没有匹配到更具体的错误类型。",
        "hint": "请查看响应中的 error/details 字段，并根据接口文档检查请求。",
    },
}


if __name__ == "__main__":
    raise SystemExit(main())
