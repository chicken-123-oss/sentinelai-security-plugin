from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_FROM_RANK = {value: key for key, value in SEVERITY_RANK.items()}


@dataclass
class ScoreResult:
    trust_score: int
    risk_score: int
    dimensions: dict[str, int]
    severity: str
    status_hint: str
    rule_matches: list[dict[str, Any]]
    signals: list[str]
    recommended_actions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "trustScore": self.trust_score,
            "riskScore": self.risk_score,
            "dimensions": self.dimensions,
            "severity": self.severity,
            "statusHint": self.status_hint,
            "ruleMatches": self.rule_matches,
            "signals": self.signals,
            "recommendedActions": self.recommended_actions,
        }


def score_event(event: dict[str, Any]) -> ScoreResult:
    dimensions = {"identity": 0, "behavior": 0, "runtime": 0, "assetImpact": 0}
    matches: list[dict[str, Any]] = []
    signals: list[str] = []
    actions: list[str] = []
    max_severity = SEVERITY_RANK.get(event.get("severityHint", "info"), 0)
    text = _event_text(event)

    def add(
        rule_id: str,
        title: str,
        *,
        identity: int = 0,
        behavior: int = 0,
        runtime: int = 0,
        asset: int = 0,
        severity: str = "medium",
        rule_signals: list[str] | None = None,
        rule_actions: list[str] | None = None,
    ) -> None:
        nonlocal max_severity
        dimensions["identity"] += identity
        dimensions["behavior"] += behavior
        dimensions["runtime"] += runtime
        dimensions["assetImpact"] += asset
        max_severity = max(max_severity, SEVERITY_RANK[severity])
        if rule_signals:
            signals.extend(rule_signals)
        if rule_actions:
            actions.extend(rule_actions)
        matches.append(
            {
                "id": rule_id,
                "title": title,
                "severity": severity,
                "signals": rule_signals or [],
                "recommendedActions": rule_actions or [],
            }
        )

    if _matches_any(text, [r"union\s+select", r"'\s*or\s*'?\d'?\s*=\s*'?\d", r"information_schema", r"sleep\s*\(", r"benchmark\s*\("]):
        add(
            "rule_sql_injection",
            "SQL injection pattern in request",
            behavior=20,
            asset=13,
            severity="high",
            rule_signals=["sql_injection"],
            rule_actions=["capture_evidence", "block_ip"],
        )

    if _matches_any(text, [r"<script", r"onerror\s*=", r"javascript:", r"document\.cookie"]):
        add(
            "rule_xss",
            "Cross-site scripting pattern in request",
            behavior=14,
            asset=6,
            severity="medium",
            rule_signals=["xss_payload"],
            rule_actions=["capture_evidence", "block_ip"],
        )

    if _matches_any(text, [r"\.\./", r"%2e%2e", r"/etc/passwd", r"boot\.ini"]):
        add(
            "rule_path_traversal",
            "Path traversal or sensitive file probing",
            behavior=13,
            asset=10,
            severity="high",
            rule_signals=["path_traversal"],
            rule_actions=["capture_evidence", "block_ip"],
        )

    if event.get("category") == "login" and ("failed_login" in event.get("labels", []) or _numeric_payload(event, "failureCount") >= 5):
        add(
            "rule_login_burst",
            "Repeated failed login activity",
            identity=18,
            behavior=5,
            severity="high",
            rule_signals=["credential_attack"],
            rule_actions=["capture_evidence", "block_ip"],
        )

    if "impossible_travel" in event.get("labels", []) or "new_geo_admin_login" in event.get("labels", []):
        add(
            "rule_unusual_admin_login",
            "Unusual privileged login context",
            identity=15,
            behavior=7,
            severity="high",
            rule_signals=["identity_anomaly"],
            rule_actions=["capture_evidence", "disable_account"],
        )

    sensitive_files = (".env", "wp-config.php", "settings.py", "config.php", "id_rsa", "authorized_keys", "web.config")
    asset_id = str(event.get("asset", {}).get("id", "")).lower()
    if event.get("category") == "file_change" and any(name in asset_id for name in sensitive_files):
        add(
            "rule_sensitive_file_change",
            "Sensitive file changed",
            runtime=10,
            asset=18,
            severity="critical",
            rule_signals=["sensitive_file_change"],
            rule_actions=["capture_evidence", "quarantine_file"],
        )

    if event.get("category") == "file_access" and any(name in asset_id for name in sensitive_files):
        add(
            "rule_sensitive_file_access",
            "Sensitive file read attempt",
            behavior=8,
            asset=15,
            severity="high",
            rule_signals=["sensitive_config_access"],
            rule_actions=["capture_evidence"],
        )

    if event.get("category") == "proc_spawn" and _matches_any(text, [r"\bwww-data\b.*\b(sh|bash|cmd\.exe|powershell)\b", r"\bphp\b.*\b(system|exec|shell_exec)\b", r"\bpython\b.*-c"]):
        add(
            "rule_web_process_shell",
            "Web process spawned an interactive shell or script runner",
            behavior=10,
            runtime=20,
            asset=8,
            severity="critical",
            rule_signals=["web_process_shell"],
            rule_actions=["capture_evidence", "stop_process"],
        )

    if event.get("category") == "connection" and ("c2" in event.get("labels", []) or "threat_feed_match" in event.get("labels", [])):
        add(
            "rule_suspicious_egress",
            "Suspicious outbound connection",
            behavior=14,
            runtime=10,
            severity="high",
            rule_signals=["suspicious_egress"],
            rule_actions=["capture_evidence", "block_ip"],
        )

    if event.get("category") == "config_change" and ("new_admin" in event.get("labels", []) or "role=admin" in text):
        add(
            "rule_new_admin_account",
            "Privileged account was added or changed",
            identity=15,
            asset=10,
            severity="high",
            rule_signals=["privilege_change"],
            rule_actions=["capture_evidence", "disable_account"],
        )

    if event.get("category") == "ioc_match" or event.get("source") == "threat_feed":
        add(
            "rule_ioc_match",
            "Known indicator matched",
            behavior=20,
            runtime=10,
            severity="critical",
            rule_signals=["ioc_match"],
            rule_actions=["capture_evidence", "block_ip"],
        )

    _apply_context_weights(event, dimensions)
    capped_dimensions = {key: min(25, value) for key, value in dimensions.items()}
    risk_score = min(100, sum(capped_dimensions.values()))
    trust_score = max(0, 100 - risk_score)
    severity = _severity_from_score(trust_score, max_severity)
    status_hint = _status_from_trust(trust_score)

    if risk_score >= 25 and "capture_evidence" not in actions:
        actions.insert(0, "capture_evidence")

    return ScoreResult(
        trust_score=trust_score,
        risk_score=risk_score,
        dimensions=capped_dimensions,
        severity=severity,
        status_hint=status_hint,
        rule_matches=matches,
        signals=_dedupe(signals),
        recommended_actions=_dedupe(actions),
    )


def _apply_context_weights(event: dict[str, Any], dimensions: dict[str, int]) -> None:
    hint_weights = {"info": 0, "low": 2, "medium": 5, "high": 10, "critical": 15}
    trust_weights = {"high": 0, "medium": 2, "unknown": 4, "low": 7}
    hint = hint_weights.get(event.get("severityHint", "info"), 0)
    trust = trust_weights.get(event.get("trustLabel", "unknown"), 4)
    dimensions["behavior"] += hint
    dimensions["identity"] += trust
    if event.get("asset", {}).get("kind") in {"account", "service"}:
        dimensions["assetImpact"] += 3


def _event_text(event: dict[str, Any]) -> str:
    fields = [
        event.get("source", ""),
        event.get("category", ""),
        event.get("severityHint", ""),
        " ".join(event.get("labels", [])),
        event.get("actor", {}).get("id", ""),
        event.get("actor", {}).get("ip", ""),
        event.get("asset", {}).get("id", ""),
        json.dumps(event.get("redactedPayload", {}), sort_keys=True),
    ]
    return " ".join(str(item).lower() for item in fields)


def _matches_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def _numeric_payload(event: dict[str, Any], key: str) -> float:
    value = event.get("redactedPayload", {}).get(key)
    if isinstance(value, (int, float)):
        return float(value)
    return 0.0


def _severity_from_score(trust_score: int, current_rank: int) -> str:
    if trust_score < 30:
        current_rank = max(current_rank, SEVERITY_RANK["critical"])
    elif trust_score < 60:
        current_rank = max(current_rank, SEVERITY_RANK["high"])
    elif trust_score < 90:
        current_rank = max(current_rank, SEVERITY_RANK["medium"])
    return SEVERITY_FROM_RANK[current_rank]


def _status_from_trust(trust_score: int) -> str:
    if trust_score < 30:
        return "containment_recommended"
    if trust_score < 60:
        return "needs_approval"
    if trust_score < 90:
        return "watch"
    return "observe"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
