from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Protocol


class LLMAdapter(Protocol):
    def analyze(self, event: dict[str, Any], score: dict[str, Any]) -> dict[str, Any]:
        ...


class HeuristicLLMAdapter:
    """Offline structured analysis adapter used when no external LLM is configured."""

    name = "Offline Heuristic Analyzer"

    def analyze(self, event: dict[str, Any], score: dict[str, Any]) -> dict[str, Any]:
        trust_score = int(score.get("trustScore", 100))
        if trust_score < 30:
            verdict = "confirmed_compromise"
            confidence = 0.86
        elif trust_score < 60:
            verdict = "suspicious"
            confidence = 0.74
        elif trust_score < 90:
            verdict = "suspicious"
            confidence = 0.55
        else:
            verdict = "benign"
            confidence = 0.42

        signals = score.get("signals", [])
        source = event.get("source", "unknown")
        category = event.get("category", "manual_review")
        if signals:
            summary = f"{category} event from {source} matched {', '.join(signals)}."
        else:
            summary = f"{category} event from {source} did not match a critical rule."

        return {
            "provider": self.name,
            "verdict": verdict,
            "confidence": confidence,
            "summary": summary,
            "evidenceSignals": signals,
            "recommendedActions": [{"actionId": action_id, "reason": "recommended by deterministic scoring"} for action_id in score.get("recommendedActions", [])],
            "requiresHumanApproval": trust_score < 60,
            "llmAvailable": False,
            "fallbackUsed": True,
        }


class OpenAICompatibleAdapter:
    name = "OpenAI-Compatible Analyzer"

    def __init__(self, profile: dict[str, Any]):
        self.profile = profile
        self.fallback = HeuristicLLMAdapter()

    def analyze(self, event: dict[str, Any], score: dict[str, Any]) -> dict[str, Any]:
        endpoint = str(self.profile.get("endpoint") or "").rstrip("/")
        if not endpoint:
            return self._fallback(event, score, "missing endpoint")
        api_key = _secret_value(str(self.profile.get("apiKeySecretRef") or ""))
        url = endpoint if endpoint.endswith("/chat/completions") else f"{endpoint}/chat/completions"
        body = {
            "model": self.profile.get("model") or "default",
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security incident analyst. Return compact JSON only with "
                        "verdict, confidence, summary, evidenceSignals, recommendedActions, "
                        "and requiresHumanApproval. Do not execute actions."
                    ),
                },
                {"role": "user", "content": json.dumps({"event": event, "score": score}, sort_keys=True)},
            ],
        }
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            request = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(request, timeout=12) as response:
                payload = json.loads(response.read().decode("utf-8"))
            content = payload["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            return _normalize_model_result(parsed, self.profile.get("name") or self.name)
        except (KeyError, json.JSONDecodeError, TimeoutError, urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            return self._fallback(event, score, f"model fallback: {exc}")

    def _fallback(self, event: dict[str, Any], score: dict[str, Any], reason: str) -> dict[str, Any]:
        result = self.fallback.analyze(event, score)
        result["provider"] = self.profile.get("name") or self.name
        result["fallbackReason"] = reason
        return result


class OllamaAdapter:
    name = "Ollama Analyzer"

    def __init__(self, profile: dict[str, Any]):
        self.profile = profile
        self.fallback = HeuristicLLMAdapter()

    def analyze(self, event: dict[str, Any], score: dict[str, Any]) -> dict[str, Any]:
        endpoint = str(self.profile.get("endpoint") or "http://127.0.0.1:11434").rstrip("/")
        body = {
            "model": self.profile.get("model") or "llama3",
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": "Return JSON only. Analyze the security event and never execute actions."},
                {"role": "user", "content": json.dumps({"event": event, "score": score}, sort_keys=True)},
            ],
        }
        try:
            request = urllib.request.Request(
                f"{endpoint}/api/chat",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=12) as response:
                payload = json.loads(response.read().decode("utf-8"))
            parsed = json.loads(payload["message"]["content"])
            return _normalize_model_result(parsed, self.profile.get("name") or self.name)
        except (KeyError, json.JSONDecodeError, TimeoutError, urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            result = self.fallback.analyze(event, score)
            result["provider"] = self.profile.get("name") or self.name
            result["fallbackReason"] = f"model fallback: {exc}"
            return result


def build_adapter(profile: dict[str, Any] | None = None) -> LLMAdapter:
    provider_type = str((profile or {}).get("providerType") or "offline_heuristic")
    if provider_type in {"openai", "azure_openai", "openai_compatible", "vllm"}:
        return OpenAICompatibleAdapter(profile or {})
    if provider_type == "ollama":
        return OllamaAdapter(profile or {})
    return HeuristicLLMAdapter()


def _secret_value(secret_ref: str) -> str:
    if not secret_ref:
        return ""
    return os.getenv(secret_ref, "")


def _normalize_model_result(raw: dict[str, Any], provider_name: str) -> dict[str, Any]:
    recommended = raw.get("recommendedActions")
    if not isinstance(recommended, list):
        recommended = []
    normalized_actions = []
    for item in recommended:
        if isinstance(item, dict) and item.get("actionId"):
            normalized_actions.append({"actionId": str(item["actionId"]), "reason": str(item.get("reason") or "model recommendation")})
        elif isinstance(item, str):
            normalized_actions.append({"actionId": item, "reason": "model recommendation"})

    return {
        "provider": provider_name,
        "verdict": str(raw.get("verdict") or "suspicious"),
        "confidence": float(raw.get("confidence") or 0.5),
        "summary": str(raw.get("summary") or "Model returned a structured analysis."),
        "evidenceSignals": raw.get("evidenceSignals") if isinstance(raw.get("evidenceSignals"), list) else [],
        "recommendedActions": normalized_actions,
        "requiresHumanApproval": bool(raw.get("requiresHumanApproval", True)),
        "llmAvailable": True,
        "fallbackUsed": False,
    }
