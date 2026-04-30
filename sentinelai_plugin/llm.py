from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Protocol


class LLMAdapter(Protocol):
    def analyze(self, event: dict[str, Any], score: dict[str, Any]) -> dict[str, Any]:
        ...

    def chat(self, messages: list[dict[str, str]], context: dict[str, Any]) -> dict[str, Any]:
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

    def chat(self, messages: list[dict[str, str]], context: dict[str, Any]) -> dict[str, Any]:
        latest = _latest_user_message(messages)
        wants_zh = _contains_cjk(latest)
        counts = context.get("counts") if isinstance(context.get("counts"), dict) else {}
        active_provider = context.get("activeProvider") if isinstance(context.get("activeProvider"), dict) else {}
        agent = context.get("agent") if isinstance(context.get("agent"), dict) else None
        incidents = context.get("incidents") if isinstance(context.get("incidents"), list) else []
        visitors = context.get("visitors") if isinstance(context.get("visitors"), list) else []
        latest_incident = incidents[0] if incidents else None
        latest_visitor = visitors[0] if visitors else None
        provider_name = active_provider.get("name") or self.name
        provider_model = active_provider.get("model") or "sentinelai-offline-v1"

        if wants_zh:
            agent_part = (
                f"当前站点上下文代理为 {agent.get('name')} ({agent.get('id')})，状态 {agent.get('status')}，最后心跳 {agent.get('lastSeen')}。"
                if agent
                else "当前没有可用的托管站点代理上下文。"
            )
            base = (
                f"我正在使用 {provider_name} / {provider_model} 的离线安全助手模式回答。"
                f"{agent_part} 当前共有 {counts.get('incidents', 0)} 个事件、{counts.get('events', 0)} 条监控内容、"
                f"{counts.get('visitors', 0)} 个去重访客。"
            )
            if any(word in latest for word in ("访客", "访问", "visitor")) and latest_visitor:
                return _chat_result(
                    self.name,
                    f"{base} 最近访客是 {latest_visitor['ip']}，访问 {latest_visitor['method']} {latest_visitor['path']}，累计 {latest_visitor['visitCount']} 次。",
                    llm_available=False,
                )
            if any(word in latest for word in ("事件", "告警", "风险", "incident")) and latest_incident:
                return _chat_result(
                    self.name,
                    f"{base} 最新事件为 {latest_incident['title']}，严重级别 {latest_incident['severity']}，状态 {latest_incident['status']}，信任分 {latest_incident['trustScore']}。",
                    llm_available=False,
                )
            return _chat_result(self.name, f"{base} 你可以继续询问事件、访客、模型配置或托管站点状态。", llm_available=False)

        agent_part = (
            f"Managed-site context agent: {agent.get('name')} ({agent.get('id')}) is {agent.get('status')}, last seen {agent.get('lastSeen')}. "
            if agent
            else "No managed-site agent context is available. "
        )
        base = (
            f"I am answering through the offline security assistant mode for {provider_name} / {provider_model}. "
            f"{agent_part}Current data: {counts.get('incidents', 0)} incidents, {counts.get('events', 0)} monitored events, "
            f"{counts.get('visitors', 0)} deduplicated visitors."
        )
        lower = latest.lower()
        if "visitor" in lower and latest_visitor:
            return _chat_result(
                self.name,
                f"{base} Latest visitor: {latest_visitor['ip']} on {latest_visitor['method']} {latest_visitor['path']}, seen {latest_visitor['visitCount']} times.",
                llm_available=False,
            )
        if any(word in lower for word in ("incident", "risk", "alert", "event")) and latest_incident:
            return _chat_result(
                self.name,
                f"{base} Latest incident: {latest_incident['title']} ({latest_incident['severity']}, {latest_incident['status']}), trust score {latest_incident['trustScore']}.",
                llm_available=False,
            )
        return _chat_result(self.name, f"{base} Ask me about incidents, visitors, model access, or managed-site status.", llm_available=False)


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

    def chat(self, messages: list[dict[str, str]], context: dict[str, Any]) -> dict[str, Any]:
        endpoint = str(self.profile.get("endpoint") or "").rstrip("/")
        if not endpoint:
            return self._chat_fallback(messages, context, "missing endpoint")
        api_key = _secret_value(str(self.profile.get("apiKeySecretRef") or ""))
        url = endpoint if endpoint.endswith("/chat/completions") else f"{endpoint}/chat/completions"
        body = {
            "model": self.profile.get("model") or "default",
            "temperature": 0.2,
            "messages": _chat_messages(messages, context),
        }
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            request = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
            content = str(payload["choices"][0]["message"]["content"]).strip()
            return _chat_result(self.profile.get("name") or self.name, content, llm_available=True)
        except (KeyError, json.JSONDecodeError, TimeoutError, urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            return self._chat_fallback(messages, context, f"model chat fallback: {exc}")

    def _fallback(self, event: dict[str, Any], score: dict[str, Any], reason: str) -> dict[str, Any]:
        result = self.fallback.analyze(event, score)
        result["provider"] = self.profile.get("name") or self.name
        result["fallbackReason"] = reason
        return result

    def _chat_fallback(self, messages: list[dict[str, str]], context: dict[str, Any], reason: str) -> dict[str, Any]:
        result = self.fallback.chat(messages, {**context, "activeProvider": self.profile})
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

    def chat(self, messages: list[dict[str, str]], context: dict[str, Any]) -> dict[str, Any]:
        endpoint = str(self.profile.get("endpoint") or "http://127.0.0.1:11434").rstrip("/")
        body = {
            "model": self.profile.get("model") or "llama3",
            "stream": False,
            "messages": _chat_messages(messages, context),
        }
        try:
            request = urllib.request.Request(
                f"{endpoint}/api/chat",
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
            content = str(payload["message"]["content"]).strip()
            return _chat_result(self.profile.get("name") or self.name, content, llm_available=True)
        except (KeyError, json.JSONDecodeError, TimeoutError, urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
            result = self.fallback.chat(messages, {**context, "activeProvider": self.profile})
            result["provider"] = self.profile.get("name") or self.name
            result["fallbackReason"] = f"model chat fallback: {exc}"
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


def _chat_messages(messages: list[dict[str, str]], context: dict[str, Any]) -> list[dict[str, str]]:
    safe_context = {
        "counts": context.get("counts"),
        "activeProvider": context.get("activeProvider"),
        "agent": context.get("agent"),
        "incidents": context.get("incidents"),
        "visitors": context.get("visitors"),
    }
    system = (
        "You are the connected AI assistant inside SentinelAI Security Plugin. "
        "Answer the operator's chat question using the current monitored website security context. "
        "Do not claim to execute remediation actions, do not expose secrets, and keep answers concise. "
        "If the user writes Chinese, answer in Chinese; otherwise answer in English."
    )
    normalized = [{"role": "system", "content": system}]
    normalized.append({"role": "system", "content": f"Current SentinelAI context JSON: {json.dumps(safe_context, ensure_ascii=False, sort_keys=True)}"})
    for item in messages[-12:]:
        role = item.get("role", "user")
        normalized.append({"role": "assistant" if role in {"assistant", "agent", "ai"} else "user", "content": str(item.get("content") or item.get("message") or "")[:4000]})
    return normalized


def _latest_user_message(messages: list[dict[str, str]]) -> str:
    for item in reversed(messages):
        role = item.get("role", "user")
        if role in {"user", "operator"}:
            return str(item.get("content") or item.get("message") or "")
    return ""


def _chat_result(provider: str, content: str, *, llm_available: bool) -> dict[str, Any]:
    return {
        "provider": provider,
        "content": content or "No answer was returned.",
        "llmAvailable": llm_available,
        "fallbackUsed": not llm_available,
    }


def _contains_cjk(value: str) -> bool:
    return any("\u4e00" <= char <= "\u9fff" for char in value)
