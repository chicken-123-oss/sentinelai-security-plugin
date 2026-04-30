from __future__ import annotations

from typing import Any

from .pipeline import process_event
from .storage import Storage


def demo_events() -> list[dict[str, Any]]:
    return [
        {
            "source": "nginx",
            "category": "request",
            "trustLabel": "low",
            "severityHint": "high",
            "actor": {"type": "ip", "id": "203.0.113.44", "ip": "203.0.113.44"},
            "asset": {"kind": "site", "id": "/wp-login.php"},
            "labels": ["admin_panel"],
            "payload": {"method": "POST", "path": "/wp-login.php", "body": "username=admin' OR '1'='1&password=redacted"},
        },
        {
            "source": "file",
            "category": "file_change",
            "trustLabel": "unknown",
            "severityHint": "critical",
            "actor": {"type": "process", "id": "php-fpm", "ip": ""},
            "asset": {"kind": "file", "id": "data/sandbox/wp-config.php"},
            "labels": ["credential_access"],
            "payload": {"changeType": "modified", "sha256": "demo"},
        },
        {
            "source": "process",
            "category": "proc_spawn",
            "trustLabel": "low",
            "severityHint": "critical",
            "actor": {"type": "process", "id": "www-data", "ip": ""},
            "asset": {"kind": "process", "id": "php-fpm"},
            "labels": ["runtime_defense"],
            "payload": {"command": "www-data php -r shell_exec('/bin/sh')", "pid": 4242},
        },
        {
            "source": "auth",
            "category": "login",
            "trustLabel": "medium",
            "severityHint": "medium",
            "actor": {"type": "user", "id": "admin@example.com", "ip": "198.51.100.9"},
            "asset": {"kind": "account", "id": "admin@example.com"},
            "labels": ["failed_login"],
            "payload": {"failureCount": 8, "windowMinutes": 5},
        },
    ]


def seed_demo(storage: Storage) -> int:
    storage.ensure_defaults()
    if storage.count_incidents() > 0:
        return 0
    count = 0
    for event in demo_events():
        process_event(storage, event, actor="demo-seed")
        count += 1
    return count

