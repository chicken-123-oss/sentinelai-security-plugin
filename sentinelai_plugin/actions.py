from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from .policy import ACTION_CATALOG


def execute_action(
    action_id: str,
    parameters: dict[str, Any],
    incident: dict[str, Any],
    data_dir: Path,
    *,
    allow_system_actions: bool = False,
) -> dict[str, Any]:
    if action_id not in ACTION_CATALOG:
        return {"ok": False, "error": "unknown action"}

    valid, message = validate_action(action_id, parameters, data_dir)
    if not valid:
        return {"ok": False, "error": message}

    evidence_dir = data_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    if action_id == "capture_evidence":
        target = evidence_dir / f"{incident['id']}.json"
        target.write_text(json.dumps(incident, indent=2, sort_keys=True), encoding="utf-8")
        return {"ok": True, "mode": "local", "artifact": str(target), "message": "redacted evidence captured"}

    if action_id == "block_ip":
        registry = data_dir / "blocked_ips.json"
        existing = _read_json_list(registry)
        ip_value = parameters["ip"]
        if ip_value not in existing:
            existing.append(ip_value)
        registry.write_text(json.dumps(existing, indent=2), encoding="utf-8")
        return {"ok": True, "mode": "simulated_connector", "message": f"IP {ip_value} added to local block registry"}

    if action_id == "quarantine_file":
        source = Path(parameters["path"]).resolve()
        if not allow_system_actions:
            return {"ok": True, "mode": "dry_run", "message": f"quarantine validated for {source}; system actions disabled"}
        quarantine_dir = data_dir / "quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        target = quarantine_dir / source.name
        shutil.move(str(source), str(target))
        return {"ok": True, "mode": "local", "artifact": str(target), "message": "file quarantined"}

    return {
        "ok": True,
        "mode": "simulated_connector",
        "message": f"{action_id} validated and recorded; connect a production executor to perform it",
    }


def validate_action(action_id: str, parameters: dict[str, Any], data_dir: Path) -> tuple[bool, str]:
    if action_id == "capture_evidence":
        return True, "ok"
    if action_id == "block_ip":
        try:
            ipaddress.ip_address(str(parameters.get("ip", "")))
        except ValueError:
            return False, "ip must be a valid IPv4 or IPv6 address"
        return True, "ok"
    if action_id == "disable_account":
        return _validate_regex(parameters.get("accountId"), r"^[a-zA-Z0-9_.@:-]{3,160}$", "accountId")
    if action_id == "quarantine_file":
        path_value = parameters.get("path")
        if not path_value:
            return False, "path is required"
        resolved = Path(str(path_value)).resolve()
        allowlist = _allowed_paths(data_dir)
        if not any(_is_relative_to(resolved, allowed) for allowed in allowlist):
            return False, "path is outside the configured allowlist"
        return True, "ok"
    if action_id == "stop_process":
        pid = parameters.get("pid")
        if not isinstance(pid, int) or pid < 1:
            return False, "pid must be a positive integer"
        return True, "ok"
    if action_id == "restart_service":
        service = str(parameters.get("service", ""))
        allowed = {item.strip() for item in os.getenv("SENTINELAI_ALLOWED_SERVICES", "").split(",") if item.strip()}
        if service and service in allowed:
            return True, "ok"
        return False, "service is not in SENTINELAI_ALLOWED_SERVICES"
    if action_id == "revoke_credential":
        return _validate_regex(parameters.get("credentialRef"), r"^[a-zA-Z0-9_.:/@-]{3,200}$", "credentialRef")
    if action_id == "enter_maintenance_mode":
        return _validate_regex(parameters.get("siteId"), r"^[a-zA-Z0-9_.:-]{3,120}$", "siteId")
    if action_id == "rollback_release":
        return _validate_regex(parameters.get("releaseId"), r"^[a-zA-Z0-9_.:-]{3,120}$", "releaseId")
    return False, "unknown action"


def _validate_regex(value: Any, pattern: str, field_name: str) -> tuple[bool, str]:
    if isinstance(value, str) and re.match(pattern, value):
        return True, "ok"
    return False, f"{field_name} is missing or invalid"


def _allowed_paths(data_dir: Path) -> list[Path]:
    paths = [data_dir.resolve()]
    for item in os.getenv("SENTINELAI_ALLOWED_PATHS", "").split(os.pathsep):
        if item.strip():
            paths.append(Path(item.strip()).resolve())
    return paths


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _read_json_list(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return [str(item) for item in data]
    return []

