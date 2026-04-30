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
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class SecurityApp:
    def __init__(self, settings: Settings, storage: Storage):
        self.settings = settings
        self.storage = storage

    def dispatch(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlparse(handler.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        if not path.startswith("/static/"):
            try:
                self.storage.record_visitor(
                    handler.client_address[0],
                    handler.headers.get("User-Agent", "unknown"),
                    path,
                    handler.command,
                )
            except Exception:
                pass
        try:
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
            _send_json(handler, exc.status, {"error": exc.message})
        except json.JSONDecodeError:
            _send_json(handler, 400, {"error": "invalid JSON body"})
        except Exception as exc:  # pragma: no cover - final guard for API resilience.
            _send_json(handler, 500, {"error": "internal server error", "details": str(exc)})

    def _get(self, handler: BaseHTTPRequestHandler, path: str, query: dict[str, list[str]]) -> None:
        if path == "/":
            _send_static(handler, "index.html")
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
                    "visitors": self.storage.list_visitors(limit=24),
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
        if path == "/api/v1/events":
            self._require_view(handler)
            limit = _int_query(query, "limit", 80)
            _send_json(handler, 200, {"items": self.storage.list_events(limit=limit)})
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
    data = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
    handler.end_headers()
    if status != 204:
        handler.wfile.write(data)


def _send_static(handler: BaseHTTPRequestHandler, relative_path: str) -> None:
    safe_name = Path(relative_path).name
    if safe_name not in {"index.html", "app.js", "styles.css"}:
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
    handler.end_headers()
    handler.wfile.write(data)


def _int_query(query: dict[str, list[str]], key: str, default: int) -> int:
    try:
        return int(query.get(key, [str(default)])[0])
    except (TypeError, ValueError):
        return default


if __name__ == "__main__":
    raise SystemExit(main())
