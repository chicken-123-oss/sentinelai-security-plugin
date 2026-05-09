from __future__ import annotations

import json
import sqlite3
import threading
import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .auth import hash_answer, hash_password, make_captcha_challenge, verify_answer, verify_password
from .models import make_id, utc_now


class Storage:
    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        else:
            conn.commit()
        finally:
            conn.close()

    def init(self) -> None:
        with self._lock, self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS sites (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agents (
                    id TEXT PRIMARY KEY,
                    site_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS agent_messages (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    message TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS providers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    provider_type TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    model TEXT NOT NULL,
                    api_key_secret_ref TEXT NOT NULL,
                    supports_structured_output INTEGER NOT NULL,
                    supports_tool_calling INTEGER NOT NULL,
                    enabled INTEGER NOT NULL,
                    health TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS system_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS admin_auth (
                    email TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS captcha_challenges (
                    id TEXT PRIMARY KEY,
                    question TEXT NOT NULL,
                    choices_json TEXT NOT NULL,
                    answer_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    proof TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS visitor_records (
                    id TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    user_agent TEXT NOT NULL,
                    path TEXT NOT NULL,
                    method TEXT NOT NULL,
                    fingerprint TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    visit_count INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    site_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    category TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    trust_label TEXT NOT NULL,
                    severity_hint TEXT NOT NULL,
                    actor_json TEXT NOT NULL,
                    asset_json TEXT NOT NULL,
                    labels_json TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    raw_artifact_ref TEXT NOT NULL,
                    score_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    trust_score INTEGER NOT NULL,
                    summary TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    analysis_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(event_id) REFERENCES events(event_id)
                );

                CREATE TABLE IF NOT EXISTS action_runs (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approval_required INTEGER NOT NULL,
                    parameters_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id)
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id TEXT PRIMARY KEY,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    details_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            _ensure_column(conn, "visitor_records", "fingerprint", "TEXT")
            _ensure_column(conn, "visitor_records", "first_seen", "TEXT")
            _ensure_column(conn, "visitor_records", "last_seen", "TEXT")
            _ensure_column(conn, "visitor_records", "visit_count", "INTEGER DEFAULT 1")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_visitor_records_fingerprint ON visitor_records (fingerprint)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_messages_agent_time ON agent_messages (agent_id, created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_received_at ON events (received_at)")
            conn.execute("UPDATE visitor_records SET first_seen = COALESCE(first_seen, created_at), last_seen = COALESCE(last_seen, created_at), visit_count = COALESCE(visit_count, 1)")
            for row in conn.execute("SELECT id, ip, user_agent, path, method FROM visitor_records WHERE fingerprint IS NULL OR fingerprint = ''").fetchall():
                conn.execute(
                    "UPDATE visitor_records SET fingerprint = ? WHERE id = ?",
                    (_visitor_fingerprint(row["ip"], row["user_agent"], row["path"], row["method"]), row["id"]),
                )
            conn.commit()

    def ensure_defaults(self, admin_email: str = "admin@example.com", admin_password: str = "sentinelai") -> None:
        now = utc_now()
        with self._lock, self.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO sites (id, name, created_at) VALUES (?, ?, ?)",
                ("site_default", "Default Site", now),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO agents
                (id, site_id, name, status, policy_version, metadata_json, last_seen, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("agent_local", "site_default", "Local Host Agent", "healthy", "bundle-dev", "{}", now, now),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO providers
                (id, name, provider_type, endpoint, model, api_key_secret_ref,
                 supports_structured_output, supports_tool_calling, enabled, health, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "provider_offline",
                    "Offline Heuristic Analyzer",
                    "offline_heuristic",
                    "",
                    "sentinelai-offline-v1",
                    "",
                    1,
                    0,
                    1,
                    "healthy",
                    now,
                ),
            )
            existing = conn.execute("SELECT email FROM admin_auth LIMIT 1").fetchone()
            if existing is None:
                salt, password_hash = hash_password(admin_password)
                conn.execute(
                    "INSERT INTO admin_auth (email, password_hash, salt, updated_at) VALUES (?, ?, ?, ?)",
                    (admin_email, password_hash, salt, now),
                )
            active_provider = conn.execute("SELECT value FROM system_settings WHERE key = ?", ("active_provider_id",)).fetchone()
            if active_provider is None:
                conn.execute(
                    "INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)",
                    ("active_provider_id", "provider_offline", now),
                )
            conn.commit()

    def counts(self) -> dict[str, int]:
        with self._lock, self.connect() as conn:
            return {
                "sites": _count(conn, "sites"),
                "agents": _count(conn, "agents"),
                "providers": _count(conn, "providers"),
                "visitors": _unique_visitor_count(conn),
                "events": _count(conn, "events"),
                "incidents": _count(conn, "incidents"),
                "actionRuns": _count(conn, "action_runs"),
                "agentMessages": _count(conn, "agent_messages"),
                "auditLogs": _count(conn, "audit_logs"),
            }

    def current_time(self) -> str:
        return utc_now()

    def count_incidents(self) -> int:
        with self._lock, self.connect() as conn:
            return _count(conn, "incidents")

    def upsert_site(self, site_id: str, name: str) -> dict[str, Any]:
        now = utc_now()
        with self._lock, self.connect() as conn:
            conn.execute(
                "INSERT INTO sites (id, name, created_at) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET name = excluded.name",
                (site_id, name, now),
            )
            conn.commit()
        return {"id": site_id, "name": name, "createdAt": now}

    def register_agent(self, agent_id: str, site_id: str, name: str, metadata: dict[str, Any]) -> dict[str, Any]:
        now = utc_now()
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                INSERT INTO agents
                (id, site_id, name, status, policy_version, metadata_json, last_seen, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    site_id = excluded.site_id,
                    name = excluded.name,
                    status = excluded.status,
                    metadata_json = excluded.metadata_json,
                    last_seen = excluded.last_seen
                """,
                (agent_id, site_id, name, "registered", "bundle-dev", _dump(metadata), now, now),
            )
            conn.commit()
        return {"id": agent_id, "siteId": site_id, "name": name, "status": "registered", "lastSeen": now}

    def check_in_agent(self, agent_id: str, status: str, policy_version: str, metadata: dict[str, Any]) -> dict[str, Any]:
        now = utc_now()
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                UPDATE agents
                SET status = ?, policy_version = ?, metadata_json = ?, last_seen = ?
                WHERE id = ?
                """,
                (status, policy_version, _dump(metadata), now, agent_id),
            )
            if conn.total_changes == 0:
                conn.execute(
                    """
                    INSERT INTO agents
                    (id, site_id, name, status, policy_version, metadata_json, last_seen, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (agent_id, "site_default", agent_id, status, policy_version, _dump(metadata), now, now),
                )
            conn.commit()
        return {"id": agent_id, "status": status, "policyVersion": policy_version, "lastSeen": now}

    def list_agents(self) -> list[dict[str, Any]]:
        with self._lock, self.connect() as conn:
            rows = conn.execute("SELECT * FROM agents ORDER BY last_seen DESC").fetchall()
        return [_agent_from_row(row) for row in rows]

    def add_agent_message(self, agent_id: str, role: str, message: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        now = utc_now()
        message_id = make_id("msg")
        normalized_role = role if role in {"user", "agent", "system"} else "system"
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                INSERT INTO agent_messages (id, agent_id, role, message, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (message_id, agent_id[:120], normalized_role, message[:4000], _dump(metadata or {}), now),
            )
            conn.commit()
        return {
            "id": message_id,
            "agentId": agent_id[:120],
            "role": normalized_role,
            "message": message[:4000],
            "metadata": metadata or {},
            "createdAt": now,
        }

    def list_agent_messages(self, agent_id: str, limit: int = 80) -> list[dict[str, Any]]:
        capped_limit = max(1, min(limit, 200))
        with self._lock, self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM (
                    SELECT rowid AS _rowid, * FROM agent_messages
                    WHERE agent_id = ?
                    ORDER BY created_at DESC, rowid DESC
                    LIMIT ?
                )
                ORDER BY created_at ASC, _rowid ASC
                """,
                (agent_id[:120], capped_limit),
            ).fetchall()
        return [_agent_message_from_row(row) for row in rows]

    def create_provider(self, provider: dict[str, Any]) -> dict[str, Any]:
        now = utc_now()
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                INSERT INTO providers
                (id, name, provider_type, endpoint, model, api_key_secret_ref,
                 supports_structured_output, supports_tool_calling, enabled, health, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    provider_type = excluded.provider_type,
                    endpoint = excluded.endpoint,
                    model = excluded.model,
                    api_key_secret_ref = excluded.api_key_secret_ref,
                    supports_structured_output = excluded.supports_structured_output,
                    supports_tool_calling = excluded.supports_tool_calling,
                    enabled = excluded.enabled
                """,
                (
                    provider["id"],
                    provider["name"],
                    provider["providerType"],
                    provider["endpoint"],
                    provider["model"],
                    provider["apiKeySecretRef"],
                    int(provider["supportsStructuredOutput"]),
                    int(provider["supportsToolCalling"]),
                    int(provider["enabled"]),
                    "configured",
                    now,
                ),
            )
            if provider["enabled"]:
                conn.execute(
                    "INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                    ("active_provider_id", provider["id"], now),
                )
            conn.commit()
        provider["health"] = "configured"
        provider["createdAt"] = now
        provider["active"] = bool(provider["enabled"])
        return provider

    def list_providers(self) -> list[dict[str, Any]]:
        with self._lock, self.connect() as conn:
            rows = conn.execute("SELECT * FROM providers ORDER BY created_at DESC").fetchall()
            active = self._get_setting(conn, "active_provider_id", "provider_offline")
        return [_provider_from_row(row, active_provider_id=active) for row in rows]

    def activate_provider(self, provider_id: str) -> dict[str, Any] | None:
        now = utc_now()
        with self._lock, self.connect() as conn:
            row = conn.execute("SELECT * FROM providers WHERE id = ?", (provider_id,)).fetchone()
            if row is None:
                return None
            conn.execute("UPDATE providers SET enabled = 1 WHERE id = ?", (provider_id,))
            conn.execute(
                "INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                ("active_provider_id", provider_id, now),
            )
            conn.commit()
        provider = _provider_from_row(row, active_provider_id=provider_id)
        provider["enabled"] = True
        provider["active"] = True
        return provider

    def get_active_provider(self) -> dict[str, Any] | None:
        with self._lock, self.connect() as conn:
            provider_id = self._get_setting(conn, "active_provider_id", "provider_offline")
            row = conn.execute("SELECT * FROM providers WHERE id = ?", (provider_id,)).fetchone()
        return _provider_from_row(row, active_provider_id=provider_id) if row is not None else None

    def store_event_bundle(
        self,
        event: dict[str, Any],
        score: dict[str, Any],
        analysis: dict[str, Any],
        action_runs: list[dict[str, Any]],
        *,
        actor: str,
    ) -> str:
        now = utc_now()
        incident_id = make_id("inc")
        title = _incident_title(event, score)
        summary = str(analysis.get("summary") or title)
        evidence = {"event": event, "score": score}
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO events
                (event_id, tenant_id, site_id, agent_id, source, category, observed_at, received_at,
                 trust_label, severity_hint, actor_json, asset_json, labels_json, payload_json,
                 raw_artifact_ref, score_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["eventId"],
                    event["tenantId"],
                    event["siteId"],
                    event["agentId"],
                    event["source"],
                    event["category"],
                    event["observedAt"],
                    event["receivedAt"],
                    event["trustLabel"],
                    event["severityHint"],
                    _dump(event["actor"]),
                    _dump(event["asset"]),
                    _dump(event["labels"]),
                    _dump(event["redactedPayload"]),
                    event.get("rawArtifactRef", ""),
                    _dump(score),
                ),
            )
            conn.execute(
                """
                INSERT INTO incidents
                (id, event_id, title, status, severity, trust_score, summary, evidence_json, analysis_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    event["eventId"],
                    title,
                    score["statusHint"],
                    score["severity"],
                    score["trustScore"],
                    summary,
                    _dump(evidence),
                    _dump(analysis),
                    now,
                    now,
                ),
            )
            for run in action_runs:
                conn.execute(
                    """
                    INSERT INTO action_runs
                    (id, incident_id, action_id, status, approval_required, parameters_json, result_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run["id"],
                        incident_id,
                        run["actionId"],
                        run["status"],
                        int(run["approvalRequired"]),
                        _dump(run.get("parameters", {})),
                        "{}",
                        now,
                        now,
                    ),
                )
            conn.execute(
                """
                INSERT INTO audit_logs (id, actor, action, target, details_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (make_id("aud"), actor, "event.ingested", incident_id, _dump({"eventId": event["eventId"], "score": score}), now),
            )
            conn.commit()
        return incident_id

    def list_incidents(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock, self.connect() as conn:
            rows = conn.execute(
                """
                SELECT i.*, e.source, e.category
                FROM incidents i
                LEFT JOIN events e ON e.event_id = i.event_id
                ORDER BY i.created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [_incident_summary_from_row(row) for row in rows]

    def list_events(self, limit: int = 80) -> list[dict[str, Any]]:
        with self._lock, self.connect() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY received_at DESC LIMIT ?", (limit,)).fetchall()
        return [_event_from_row(row) for row in rows]

    def list_event_index(self, limit: int = 160) -> dict[str, Any]:
        capped_limit = max(1, min(limit, 500))
        with self._lock, self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY received_at DESC LIMIT ?",
                (max(capped_limit * 4, capped_limit),),
            ).fetchall()
        raw_events = [_event_from_row(row) for row in rows]
        unique_events: list[dict[str, Any]] = []
        by_key: dict[str, dict[str, Any]] = {}

        for event in raw_events:
            key = _event_access_fingerprint(event)
            event["dedupeKey"] = key
            event["duplicateCount"] = 1
            event["firstSeen"] = event["receivedAt"]
            event["lastSeen"] = event["receivedAt"]
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = event
                unique_events.append(event)
                continue
            existing["duplicateCount"] = int(existing.get("duplicateCount") or 1) + 1
            existing["firstSeen"] = min(str(existing.get("firstSeen") or existing["receivedAt"]), event["receivedAt"])
            existing["lastSeen"] = max(str(existing.get("lastSeen") or existing["receivedAt"]), event["receivedAt"])
            if event["priority"]["rank"] < existing["priority"]["rank"]:
                event["duplicateCount"] = existing["duplicateCount"]
                event["firstSeen"] = existing["firstSeen"]
                event["lastSeen"] = existing["lastSeen"]
                by_key[key] = event
                unique_events[unique_events.index(existing)] = event

        unique_events = sorted(unique_events, key=lambda item: str(item["lastSeen"]), reverse=True)
        unique_events = sorted(unique_events, key=lambda item: int(item["priority"]["rank"]))
        unique_events = sorted(unique_events, key=lambda item: str(item["day"]), reverse=True)
        unique_events = unique_events[:capped_limit]

        priority_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        day_map: dict[str, dict[str, Any]] = {}
        for event in unique_events:
            level = str(event["priority"]["level"])
            priority_counts[level] = priority_counts.get(level, 0) + 1
            day = str(event["day"])
            group = day_map.setdefault(day, {"day": day, "count": 0, "items": []})
            group["count"] += 1
            group["items"].append(event)

        days = sorted(day_map.values(), key=lambda item: item["day"], reverse=True)
        for day in days:
            day["items"].sort(key=lambda item: str(item["lastSeen"]), reverse=True)
            day["items"].sort(key=lambda item: int(item["priority"]["rank"]))

        return {
            "items": unique_events,
            "days": days,
            "priorityCounts": priority_counts,
            "rawEventCount": len(raw_events),
            "uniqueEventCount": len(unique_events),
            "duplicatesCollapsed": max(0, len(raw_events) - len(by_key)),
        }

    def get_incident_bundle(self, incident_id: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as conn:
            incident_row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
            if incident_row is None:
                return None
            event_row = conn.execute("SELECT * FROM events WHERE event_id = ?", (incident_row["event_id"],)).fetchone()
            action_rows = conn.execute("SELECT * FROM action_runs WHERE incident_id = ? ORDER BY created_at ASC", (incident_id,)).fetchall()
        incident = _incident_from_row(incident_row)
        incident["event"] = _event_from_row(event_row) if event_row is not None else None
        incident["actionRuns"] = [_action_from_row(row) for row in action_rows]
        return incident

    def get_action_run(self, action_run_id: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as conn:
            row = conn.execute("SELECT * FROM action_runs WHERE id = ?", (action_run_id,)).fetchone()
        return _action_from_row(row) if row is not None else None

    def update_action_run_result(self, action_run_id: str, result: dict[str, Any]) -> None:
        status = "completed" if result.get("ok") else "failed"
        now = utc_now()
        with self._lock, self.connect() as conn:
            conn.execute(
                "UPDATE action_runs SET status = ?, result_json = ?, updated_at = ? WHERE id = ?",
                (status, _dump(result), now, action_run_id),
            )
            conn.commit()

    def approve_incident(self, incident_id: str, actor: str) -> None:
        now = utc_now()
        with self._lock, self.connect() as conn:
            conn.execute("UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?", ("approved", now, incident_id))
            conn.execute(
                "UPDATE action_runs SET status = ?, updated_at = ? WHERE incident_id = ? AND status = ?",
                ("approved", now, incident_id, "pending_approval"),
            )
            conn.execute(
                "INSERT INTO audit_logs (id, actor, action, target, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (make_id("aud"), actor, "incident.approved", incident_id, "{}", now),
            )
            conn.commit()

    def reject_incident(self, incident_id: str, actor: str, reason: str = "") -> None:
        now = utc_now()
        with self._lock, self.connect() as conn:
            conn.execute("UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?", ("rejected", now, incident_id))
            conn.execute(
                "UPDATE action_runs SET status = ?, updated_at = ? WHERE incident_id = ? AND status IN ('pending_approval', 'ready', 'approved')",
                ("rejected", now, incident_id),
            )
            conn.execute(
                "INSERT INTO audit_logs (id, actor, action, target, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (make_id("aud"), actor, "incident.rejected", incident_id, _dump({"reason": reason}), now),
            )
            conn.commit()

    def add_audit(self, actor: str, action: str, target: str, details: dict[str, Any] | None = None) -> None:
        with self._lock, self.connect() as conn:
            conn.execute(
                "INSERT INTO audit_logs (id, actor, action, target, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (make_id("aud"), actor, action, target, _dump(details or {}), utc_now()),
            )
            conn.commit()

    def list_audit_logs(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self.connect() as conn:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [_audit_from_row(row) for row in rows]

    def verify_admin(self, email: str, password: str) -> bool:
        with self._lock, self.connect() as conn:
            row = conn.execute("SELECT * FROM admin_auth WHERE email = ?", (email,)).fetchone()
        if row is None:
            return False
        return verify_password(password, row["salt"], row["password_hash"])

    def change_admin_password(self, email: str, current_password: str, new_password: str) -> bool:
        if not self.verify_admin(email, current_password):
            return False
        salt, password_hash = hash_password(new_password)
        with self._lock, self.connect() as conn:
            conn.execute(
                "UPDATE admin_auth SET password_hash = ?, salt = ?, updated_at = ? WHERE email = ?",
                (password_hash, salt, utc_now(), email),
            )
            conn.commit()
        return True

    def create_captcha(self, ttl_seconds: int = 300) -> dict[str, Any]:
        challenge = make_captcha_challenge()
        salt, answer_hash = hash_answer(challenge.answer)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        expires = now + timedelta(seconds=ttl_seconds)
        captcha_id = make_id("cap")
        with self._lock, self.connect() as conn:
            conn.execute(
                """
                INSERT INTO captcha_challenges
                (id, question, choices_json, answer_hash, salt, proof, attempts, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    captcha_id,
                    challenge.question,
                    _dump(challenge.choices),
                    answer_hash,
                    salt,
                    challenge.proof,
                    0,
                    expires.isoformat().replace("+00:00", "Z"),
                    now.isoformat().replace("+00:00", "Z"),
                ),
            )
            conn.commit()
        return {
            "challengeId": captcha_id,
            "question": challenge.question,
            "choices": challenge.choices,
            "proof": challenge.proof,
            "expiresAt": expires.isoformat().replace("+00:00", "Z"),
            "mode": "math-choice-nonce",
        }

    def verify_captcha(self, challenge_id: str, answer: str) -> bool:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        with self._lock, self.connect() as conn:
            row = conn.execute("SELECT * FROM captcha_challenges WHERE id = ?", (challenge_id,)).fetchone()
            if row is None:
                return False
            expires_at = _parse_time(row["expires_at"])
            attempts = int(row["attempts"])
            if expires_at <= now or attempts >= 5:
                conn.execute("DELETE FROM captcha_challenges WHERE id = ?", (challenge_id,))
                conn.commit()
                return False
            ok = verify_answer(answer, row["salt"], row["answer_hash"])
            if ok:
                conn.execute("DELETE FROM captcha_challenges WHERE id = ?", (challenge_id,))
            else:
                conn.execute("UPDATE captcha_challenges SET attempts = attempts + 1 WHERE id = ?", (challenge_id,))
            conn.commit()
        return ok

    def record_visitor(self, ip: str, user_agent: str, path: str, method: str) -> None:
        normalized_ip = ip[:80]
        normalized_agent = user_agent[:240]
        normalized_path = path[:240]
        normalized_method = method[:16]
        fingerprint = _visitor_fingerprint(normalized_ip, normalized_agent, normalized_path, normalized_method)
        now = utc_now()
        with self._lock, self.connect() as conn:
            row = conn.execute(
                "SELECT id FROM visitor_records WHERE fingerprint = ? ORDER BY created_at DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
            if row is not None:
                conn.execute(
                    "UPDATE visitor_records SET last_seen = ?, visit_count = COALESCE(visit_count, 1) + 1 WHERE id = ?",
                    (now, row["id"]),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO visitor_records
                    (id, ip, user_agent, path, method, fingerprint, first_seen, last_seen, visit_count, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        make_id("vis"),
                        normalized_ip,
                        normalized_agent,
                        normalized_path,
                        normalized_method,
                        fingerprint,
                        now,
                        now,
                        1,
                        now,
                    ),
                )
            conn.commit()

    def list_visitors(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM visitor_records ORDER BY COALESCE(last_seen, created_at) DESC LIMIT ?",
                (max(limit * 5, limit),),
            ).fetchall()
        visitors: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in rows:
            key = row["fingerprint"] or _visitor_fingerprint(row["ip"], row["user_agent"], row["path"], row["method"])
            if key in seen:
                continue
            seen.add(key)
            visitors.append(_visitor_from_row(row))
            if len(visitors) >= limit:
                break
        return visitors

    def _get_setting(self, conn: sqlite3.Connection, key: str, default: str) -> str:
        row = conn.execute("SELECT value FROM system_settings WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row is not None else default


def _incident_title(event: dict[str, Any], score: dict[str, Any]) -> str:
    matches = score.get("ruleMatches", [])
    if matches:
        return str(matches[0].get("title") or "Security incident")
    return f"{event.get('category', 'event')} from {event.get('source', 'unknown')}"


def _count(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _unique_visitor_count(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(DISTINCT COALESCE(fingerprint, id)) FROM visitor_records").fetchone()[0])


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _load(value: str) -> Any:
    if not value:
        return None
    return json.loads(value)


def _incident_summary_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "eventId": row["event_id"],
        "title": row["title"],
        "status": row["status"],
        "severity": row["severity"],
        "trustScore": row["trust_score"],
        "summary": row["summary"],
        "source": row["source"],
        "category": row["category"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def _incident_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "eventId": row["event_id"],
        "title": row["title"],
        "status": row["status"],
        "severity": row["severity"],
        "trustScore": row["trust_score"],
        "summary": row["summary"],
        "evidence": _load(row["evidence_json"]),
        "analysis": _load(row["analysis_json"]),
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def _event_from_row(row: sqlite3.Row) -> dict[str, Any]:
    event = {
        "eventId": row["event_id"],
        "tenantId": row["tenant_id"],
        "siteId": row["site_id"],
        "agentId": row["agent_id"],
        "source": row["source"],
        "category": row["category"],
        "observedAt": row["observed_at"],
        "receivedAt": row["received_at"],
        "trustLabel": row["trust_label"],
        "severityHint": row["severity_hint"],
        "actor": _load(row["actor_json"]),
        "asset": _load(row["asset_json"]),
        "labels": _load(row["labels_json"]),
        "redactedPayload": _load(row["payload_json"]),
        "rawArtifactRef": row["raw_artifact_ref"],
        "score": _load(row["score_json"]),
    }
    event["priority"] = _event_priority(event)
    event["day"] = _event_day(str(event["receivedAt"]))
    event["attackerInput"] = _attacker_input(event)
    return event


def _action_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "incidentId": row["incident_id"],
        "actionId": row["action_id"],
        "status": row["status"],
        "approvalRequired": bool(row["approval_required"]),
        "parameters": _load(row["parameters_json"]) or {},
        "result": _load(row["result_json"]) or {},
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def _provider_from_row(row: sqlite3.Row, active_provider_id: str | None = None) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "providerType": row["provider_type"],
        "endpoint": row["endpoint"],
        "model": row["model"],
        "apiKeySecretRef": row["api_key_secret_ref"],
        "supportsStructuredOutput": bool(row["supports_structured_output"]),
        "supportsToolCalling": bool(row["supports_tool_calling"]),
        "enabled": bool(row["enabled"]),
        "health": row["health"],
        "active": row["id"] == active_provider_id,
        "createdAt": row["created_at"],
    }


def _agent_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "siteId": row["site_id"],
        "name": row["name"],
        "status": row["status"],
        "policyVersion": row["policy_version"],
        "metadata": _load(row["metadata_json"]) or {},
        "lastSeen": row["last_seen"],
        "createdAt": row["created_at"],
    }


def _agent_message_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "agentId": row["agent_id"],
        "role": row["role"],
        "message": row["message"],
        "metadata": _load(row["metadata_json"]) or {},
        "createdAt": row["created_at"],
    }


def _audit_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "actor": row["actor"],
        "action": row["action"],
        "target": row["target"],
        "details": _load(row["details_json"]) or {},
        "createdAt": row["created_at"],
    }


def _visitor_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "ip": row["ip"],
        "userAgent": row["user_agent"],
        "path": row["path"],
        "method": row["method"],
        "firstSeen": row["first_seen"] or row["created_at"],
        "lastSeen": row["last_seen"] or row["created_at"],
        "visitCount": int(row["visit_count"] or 1),
        "createdAt": row["created_at"],
    }


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _event_priority(event: dict[str, Any]) -> dict[str, Any]:
    score = event.get("score") if isinstance(event.get("score"), dict) else {}
    trust_score = int(score.get("trustScore", 100))
    risk_score = int(score.get("riskScore", max(0, 100 - trust_score)))
    severity = str(score.get("severity") or event.get("severityHint") or "info")
    if trust_score < 30 or risk_score >= 70 or severity == "critical":
        return {"rank": 0, "level": "critical", "label": "P0 Critical", "scoreBand": "trust 0-29 / risk 70-100"}
    if trust_score < 60 or risk_score >= 40 or severity == "high":
        return {"rank": 1, "level": "high", "label": "P1 High", "scoreBand": "trust 30-59 / risk 40-69"}
    if trust_score < 90 or risk_score >= 10 or severity == "medium":
        return {"rank": 2, "level": "medium", "label": "P2 Medium", "scoreBand": "trust 60-89 / risk 10-39"}
    return {"rank": 3, "level": "low", "label": "P3 Low", "scoreBand": "trust 90-100 / risk 0-9"}


def _event_day(received_at: str) -> str:
    return received_at[:10] if len(received_at) >= 10 else "unknown"


def _attacker_input(event: dict[str, Any]) -> dict[str, Any]:
    payload = event.get("redactedPayload") if isinstance(event.get("redactedPayload"), dict) else {}
    fields: dict[str, Any] = {}
    interesting_keys = (
        "method",
        "path",
        "url",
        "query",
        "queryString",
        "params",
        "body",
        "requestBody",
        "form",
        "username",
        "user",
        "command",
        "payload",
    )
    for key in interesting_keys:
        if key in payload:
            fields[key] = payload[key]
    if not fields and payload:
        fields = payload
    summary_parts = []
    for key in ("method", "path", "query", "body", "requestBody", "command", "payload"):
        value = fields.get(key)
        if value not in (None, ""):
            summary_parts.append(f"{key}={_compact_text(value)}")
    if not summary_parts:
        actor = event.get("actor") if isinstance(event.get("actor"), dict) else {}
        asset = event.get("asset") if isinstance(event.get("asset"), dict) else {}
        summary_parts = [_compact_text(actor.get("id") or actor.get("ip") or "unknown"), _compact_text(asset.get("id") or "unknown")]
    return {
        "summary": " / ".join(summary_parts)[:500],
        "fields": fields,
    }


def _compact_text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text[:180]


def _event_access_fingerprint(event: dict[str, Any]) -> str:
    actor = event.get("actor") if isinstance(event.get("actor"), dict) else {}
    asset = event.get("asset") if isinstance(event.get("asset"), dict) else {}
    payload = event.get("redactedPayload") if isinstance(event.get("redactedPayload"), dict) else {}
    material = json.dumps(
        {
            "source": event.get("source"),
            "category": event.get("category"),
            "actorIp": actor.get("ip"),
            "actorId": actor.get("id"),
            "assetId": asset.get("id"),
            "method": payload.get("method"),
            "path": payload.get("path") or asset.get("id"),
            "query": payload.get("query") or payload.get("queryString"),
            "body": payload.get("body") or payload.get("requestBody") or payload.get("payload") or payload.get("command"),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _visitor_fingerprint(ip: str, user_agent: str, path: str, method: str) -> str:
    material = json.dumps(
        {
            "ip": ip.strip().lower(),
            "userAgent": user_agent.strip().lower(),
            "path": path.strip().lower(),
            "method": method.strip().upper(),
        },
        sort_keys=True,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()
