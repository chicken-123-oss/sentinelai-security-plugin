from __future__ import annotations

from typing import Any

from .llm import LLMAdapter, build_adapter
from .models import make_id, normalize_event
from .policy import ACTION_CATALOG, initial_action_status
from .redaction import redact_payload
from .scoring import score_event
from .storage import Storage


def process_event(
    storage: Storage,
    raw_event: dict[str, Any],
    adapter: LLMAdapter | None = None,
    *,
    actor: str = "system",
) -> dict[str, Any]:
    event = normalize_event(raw_event)
    payload = raw_event.get("redactedPayload")
    if payload is None:
        payload = raw_event.get("payload", {})
    event["redactedPayload"] = redact_payload(payload if isinstance(payload, dict) else {"message": payload})

    score = score_event(event).to_dict()
    active_provider = storage.get_active_provider()
    analysis = (adapter or build_adapter(active_provider)).analyze(event, score)
    action_ids = _collect_action_ids(score, analysis)
    action_runs = [_make_action_run(action_id, event, score) for action_id in action_ids]
    action_runs = [run for run in action_runs if run is not None]
    incident_id = storage.store_event_bundle(event, score, analysis, action_runs, actor=actor)
    incident = storage.get_incident_bundle(incident_id)
    if incident is None:
        raise RuntimeError("incident was not stored")
    return incident


def _collect_action_ids(score: dict[str, Any], analysis: dict[str, Any]) -> list[str]:
    ordered: list[str] = []
    for action_id in score.get("recommendedActions", []):
        if action_id not in ordered:
            ordered.append(action_id)
    for item in analysis.get("recommendedActions", []):
        action_id = item.get("actionId") if isinstance(item, dict) else None
        if action_id and action_id not in ordered:
            ordered.append(action_id)
    return [action_id for action_id in ordered if action_id in ACTION_CATALOG]


def _make_action_run(action_id: str, event: dict[str, Any], score: dict[str, Any]) -> dict[str, Any] | None:
    parameters = _infer_parameters(action_id, event)
    if parameters is None:
        return None
    status = initial_action_status(action_id, score)
    return {
        "id": make_id("act"),
        "actionId": action_id,
        "status": status,
        "approvalRequired": status == "pending_approval",
        "parameters": parameters,
    }


def _infer_parameters(action_id: str, event: dict[str, Any]) -> dict[str, Any] | None:
    payload = event.get("redactedPayload", {})
    actor = event.get("actor", {})
    asset = event.get("asset", {})

    if action_id == "capture_evidence":
        return {"eventId": event["eventId"]}
    if action_id == "block_ip":
        ip_value = actor.get("ip")
        return {"ip": ip_value} if ip_value else None
    if action_id == "disable_account":
        account_id = actor.get("id")
        return {"accountId": account_id} if account_id and account_id != "unknown" else None
    if action_id == "quarantine_file":
        path_value = asset.get("id")
        return {"path": path_value} if path_value and path_value != "unknown" else None
    if action_id == "stop_process":
        pid = payload.get("pid") or payload.get("processId")
        return {"pid": int(pid)} if isinstance(pid, int) or (isinstance(pid, str) and pid.isdigit()) else None
    if action_id == "restart_service":
        service = payload.get("service")
        return {"service": service} if isinstance(service, str) else None
    if action_id == "revoke_credential":
        credential_ref = payload.get("credentialRef")
        return {"credentialRef": credential_ref} if isinstance(credential_ref, str) else None
    if action_id == "enter_maintenance_mode":
        return {"siteId": event.get("siteId")}
    if action_id == "rollback_release":
        release_id = payload.get("releaseId")
        return {"releaseId": release_id} if isinstance(release_id, str) else None
    return None
