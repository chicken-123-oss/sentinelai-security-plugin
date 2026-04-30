from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

JsonDict = dict[str, Any]

ALLOWED_SOURCES = {
    "nginx",
    "apache",
    "app",
    "auth",
    "file",
    "process",
    "network",
    "threat_feed",
    "manual",
    "agent",
}

ALLOWED_CATEGORIES = {
    "login",
    "request",
    "file_change",
    "file_access",
    "proc_spawn",
    "connection",
    "config_change",
    "ioc_match",
    "agent_check",
    "manual_review",
}

ALLOWED_TRUST_LABELS = {"high", "medium", "low", "unknown"}
ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical"}
ROLE_TENANT_OWNER = "TENANT_OWNER"
ROLE_SECURITY_ADMIN = "SECURITY_ADMIN"
ROLE_AUDITOR = "AUDITOR"
ROLE_AGENT = "AGENT"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _clean_enum(value: Any, allowed: set[str], default: str) -> str:
    if isinstance(value, str) and value in allowed:
        return value
    return default


def _clean_labels(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        labels = []
        for item in value:
            if isinstance(item, str) and item.strip():
                labels.append(item.strip())
        return labels
    return []


def normalize_event(raw: JsonDict) -> JsonDict:
    if not isinstance(raw, dict):
        raise ValueError("event must be a JSON object")

    actor = raw.get("actor") if isinstance(raw.get("actor"), dict) else {}
    asset = raw.get("asset") if isinstance(raw.get("asset"), dict) else {}
    now = utc_now()

    return {
        "eventId": str(raw.get("eventId") or make_id("evt")),
        "tenantId": str(raw.get("tenantId") or "tenant_local"),
        "siteId": str(raw.get("siteId") or "site_default"),
        "agentId": str(raw.get("agentId") or "agent_local"),
        "source": _clean_enum(raw.get("source"), ALLOWED_SOURCES, "manual"),
        "category": _clean_enum(raw.get("category"), ALLOWED_CATEGORIES, "manual_review"),
        "trustLabel": _clean_enum(raw.get("trustLabel"), ALLOWED_TRUST_LABELS, "unknown"),
        "severityHint": _clean_enum(raw.get("severityHint"), ALLOWED_SEVERITIES, "info"),
        "observedAt": str(raw.get("observedAt") or now),
        "receivedAt": str(raw.get("receivedAt") or now),
        "actor": {
            "type": str(actor.get("type") or "unknown"),
            "id": str(actor.get("id") or "unknown"),
            "ip": str(actor.get("ip") or ""),
        },
        "asset": {
            "kind": str(asset.get("kind") or "site"),
            "id": str(asset.get("id") or "unknown"),
        },
        "labels": _clean_labels(raw.get("labels")),
        "redactedPayload": raw.get("redactedPayload") if isinstance(raw.get("redactedPayload"), dict) else {},
        "rawArtifactRef": str(raw.get("rawArtifactRef") or ""),
    }


def normalize_provider(raw: JsonDict) -> JsonDict:
    if not isinstance(raw, dict):
        raise ValueError("provider must be a JSON object")
    provider_type = str(raw.get("providerType") or "offline_heuristic")
    return {
        "id": str(raw.get("id") or make_id("prov")),
        "name": str(raw.get("name") or "Offline Heuristic Analyzer"),
        "providerType": provider_type,
        "endpoint": str(raw.get("endpoint") or ""),
        "model": str(raw.get("model") or "sentinelai-offline-v1"),
        "apiKeySecretRef": str(raw.get("apiKeySecretRef") or ""),
        "supportsStructuredOutput": bool(raw.get("supportsStructuredOutput", True)),
        "supportsToolCalling": bool(raw.get("supportsToolCalling", False)),
        "enabled": bool(raw.get("enabled", True)),
    }

