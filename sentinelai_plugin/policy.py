from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import ROLE_AUDITOR, ROLE_SECURITY_ADMIN, ROLE_TENANT_OWNER


@dataclass(frozen=True)
class ActionDefinition:
    id: str
    approval: str
    validator: str
    high_impact: bool
    description: str


ACTION_CATALOG: dict[str, ActionDefinition] = {
    "capture_evidence": ActionDefinition("capture_evidence", "auto", "incident_ref", False, "Capture a redacted evidence bundle."),
    "block_ip": ActionDefinition("block_ip", "policy_based", "ipv4_or_ipv6", False, "Record an IP block request in the local block registry."),
    "disable_account": ActionDefinition("disable_account", "manual", "account_id", True, "Disable or suspend an account through a controlled connector."),
    "quarantine_file": ActionDefinition("quarantine_file", "manual", "safe_path_under_allowlist", True, "Move a file into quarantine when local actions are enabled."),
    "stop_process": ActionDefinition("stop_process", "manual", "pid_and_owner", True, "Stop a process after explicit approval."),
    "restart_service": ActionDefinition("restart_service", "manual", "service_in_allowlist", True, "Restart a configured service connector."),
    "revoke_credential": ActionDefinition("revoke_credential", "manual", "credential_ref", True, "Revoke a credential through a connector."),
    "enter_maintenance_mode": ActionDefinition("enter_maintenance_mode", "manual", "site_id", True, "Request site maintenance mode."),
    "rollback_release": ActionDefinition("rollback_release", "manual", "release_id", True, "Request release rollback."),
}


def role_can_operate(role: str) -> bool:
    return role in {ROLE_TENANT_OWNER, ROLE_SECURITY_ADMIN}


def role_can_configure(role: str) -> bool:
    return role == ROLE_TENANT_OWNER


def role_can_view(role: str) -> bool:
    return role in {ROLE_TENANT_OWNER, ROLE_SECURITY_ADMIN, ROLE_AUDITOR}


def initial_action_status(action_id: str, score: dict[str, Any]) -> str:
    action = ACTION_CATALOG.get(action_id)
    if action is None:
        return "rejected"
    if action.approval == "auto":
        return "ready"
    if action.approval == "policy_based" and action_id == "block_ip" and int(score.get("trustScore", 100)) < 30:
        return "ready"
    return "pending_approval"


def can_execute_action(action_run: dict[str, Any], role: str) -> tuple[bool, str]:
    if not role_can_operate(role):
        return False, "role is not allowed to execute actions"
    action_id = action_run.get("actionId")
    action = ACTION_CATALOG.get(action_id)
    if action is None:
        return False, "unknown action"
    if action_run.get("status") not in {"ready", "approved"}:
        return False, "action requires approval before execution"
    return True, "allowed"

