# SentinelAI Security Plugin - Core Technology

## Combined Architecture

The implementation combines both supplied plans into a runnable MVP:

- Plugin dashboard: a vanilla browser UI served by the Python API.
- Control plane API: a stdlib HTTP server with JSON endpoints.
- Storage and audit center: SQLite tables for events, incidents, action runs, agents, providers, and audit logs.
- Visitor telemetry: request path, method, source IP, user agent, first seen, last seen, and visit count are stored for dashboard visitor records.
- Host-agent interface: a simulator that checks in and ingests events through a bearer-token channel.
- Managed-site backend entry: a compact summary endpoint and `/managed-entry` page for existing admin portals, including a redirect button to the full SentinelAI console.
- Connected AI conversation channel: persisted operator messages and model replies through the active large-model provider, grounded in current SentinelAI state with an offline fallback.
- LLM adapter layer: an offline structured analyzer by default, with OpenAI-compatible/vLLM/Azure-style and Ollama adapters for owner-selected large model APIs.
- Policy and action center: a fixed action catalog with approval requirements and parameter validators.
- Account security: PBKDF2 password storage, owner password changes, and one-time CAPTCHA challenges.

The central design choice is rule-first security. The model layer explains and structures findings, but it does not directly execute actions.

## Event Contract

Every collector and host-agent message is normalized to one contract:

```json
{
  "eventId": "evt_...",
  "tenantId": "tenant_local",
  "siteId": "site_default",
  "agentId": "agent_local",
  "source": "nginx|apache|app|auth|file|process|network|threat_feed|manual|agent",
  "category": "login|request|file_change|file_access|proc_spawn|connection|config_change|ioc_match|agent_check|manual_review",
  "trustLabel": "high|medium|low|unknown",
  "severityHint": "info|low|medium|high|critical",
  "actor": { "type": "user|ip|process|service|unknown", "id": "value", "ip": "value" },
  "asset": { "kind": "site|host|file|process|account|service", "id": "value" },
  "labels": [],
  "redactedPayload": {}
}
```

The `payload` submitted by callers is redacted before storage. Sensitive keys such as password, token, cookie, authorization, secret, and private key are replaced with `[REDACTED]`.

## Trust Scoring

The scoring engine computes a four-dimensional risk model:

- Identity risk
- Behavior risk
- Runtime risk
- Asset impact risk

Each dimension is capped at 25. The total risk is capped at 100, and:

```text
trust_score = 100 - risk_score
```

Thresholds:

| Trust Score | Status |
| --- | --- |
| 90-100 | observe |
| 60-89 | watch |
| 30-59 | needs_approval |
| 0-29 | containment_recommended |

Rules currently detect SQL injection, XSS, path traversal, login bursts, unusual admin logins, sensitive file changes, sensitive file access, web process shell spawning, suspicious egress, privileged account changes, and IOC matches.

## LLM Adapter Layer

The MVP ships with `HeuristicLLMAdapter`, an offline adapter that returns the same structured shape expected from an external model:

```json
{
  "verdict": "benign|suspicious|confirmed_compromise",
  "confidence": 0.74,
  "summary": "short explanation",
  "evidenceSignals": ["sql_injection"],
  "recommendedActions": [
    { "actionId": "capture_evidence", "reason": "recommended by deterministic scoring" }
  ],
  "requiresHumanApproval": true
}
```

This keeps the system runnable without network access. External OpenAI-compatible, local, or hosted providers can be added behind the same adapter contract without changing ingestion, scoring, approval, or execution code.

Large model access is implemented through provider profiles:

```json
{
  "name": "Local vLLM",
  "providerType": "openai_compatible",
  "endpoint": "http://127.0.0.1:8000/v1",
  "model": "security-model",
  "apiKeySecretRef": "SENTINELAI_MODEL_KEY",
  "enabled": true
}
```

`apiKeySecretRef` is the name of an environment variable. The raw key is never stored in the database. If the provider fails or does not return valid structured JSON, the incident pipeline records a fallback reason and continues with the offline analyzer.

Ollama is supported through `/api/chat` with JSON output enabled. Anthropic and Gemini can be stored as selectable provider profiles, ready for provider-specific adapters.

## Action Catalog And Policy

There is no arbitrary shell action. The catalog is fixed:

| Action | Approval | Execution mode |
| --- | --- | --- |
| `capture_evidence` | auto | writes redacted evidence JSON |
| `block_ip` | policy_based | records a local block registry entry |
| `disable_account` | manual | simulated connector |
| `quarantine_file` | manual | dry-run unless local system actions are explicitly enabled |
| `stop_process` | manual | simulated connector |
| `restart_service` | manual | simulated connector with allowlist validation |
| `revoke_credential` | manual | simulated connector |
| `enter_maintenance_mode` | manual | simulated connector |
| `rollback_release` | manual | simulated connector |

Only owner/admin roles can approve and execute actions. Only the tenant owner can modify model providers and site configuration.

## Managed Entry And AI Chat

Managed website backends can integrate SentinelAI without reimplementing the whole dashboard. `GET /api/v1/managed-site/summary` returns a compact payload containing status counts, active model provider, recent incidents, recent visitors, connected agents, recent audit entries, `consoleUrl`, `managedEntryUrl`, and a localized redirect button definition. The static `/managed-entry` page consumes the same API and can be linked or embedded in a trusted admin portal.

The plugin dashboard also includes an AI Chat view. It loads connected managed-site agents from `/api/v1/agents` as context, stores conversation history in the `agent_messages` SQLite table, and sends operator questions to `POST /api/v1/ai/chat`. Replies are generated by the currently active LLM adapter: OpenAI-compatible/vLLM/Azure-style endpoints, Ollama, or the offline heuristic adapter. SentinelAI sends compact context containing agent heartbeat, policy version, incident counts, visitor counts, latest incidents, latest visitors, and active provider metadata. The compatibility route `/api/v1/agent/chat` is still accepted.

## Security Boundaries

- Inputs are validated and normalized at ingestion.
- Payloads are redacted before persistence.
- Visitor records are fingerprinted by IP, user agent, path, and method; duplicate scanner or polling hits update counters rather than creating duplicate rows.
- Managed entry summaries can be read with admin, auditor, or ingest tokens; production portals should call this server side rather than exposing long-lived tokens in browser JavaScript.
- Agent chat writes an audit record and requires owner/admin permission for new messages; auditors can read existing history.
- Login requires a one-time CAPTCHA challenge and a valid password.
- Passwords are stored with PBKDF2-HMAC-SHA256 and per-password salt.
- The LLM adapter cannot directly execute actions.
- High-impact actions require human approval.
- Action parameters are validated by type, path allowlist, service allowlist, or regex.
- Audit records are written for login, ingestion, agent registration/check-in, provider updates, incident decisions, and action execution.
- Default execution mode avoids host mutation.

## Files Of Interest

- `sentinelai_plugin/server.py`: HTTP API, auth gates, dashboard serving.
- `sentinelai_plugin/auth.py`: password hashing, validation, and CAPTCHA generation.
- `sentinelai_plugin/scoring.py`: rule-first trust scoring engine.
- `sentinelai_plugin/pipeline.py`: normalization, redaction, scoring, analysis, action-run creation.
- `sentinelai_plugin/policy.py`: RBAC and action policy.
- `sentinelai_plugin/actions.py`: safe action validators and executors.
- `sentinelai_plugin/storage.py`: SQLite schema and persistence.
- `sentinelai_plugin/agent.py`: host-agent simulator.
- `sentinelai_plugin/static/`: dashboard frontend and managed-entry frontend.

## Frontend Experience

The UI provides English and Chinese language options. Its visual treatment is a high-contrast tactical console inspired by the referenced Arknights webpage: strong black/white/red contrast, large uppercase headings, `://` command labels, angular panels, dense lists, and live-status indicators. It does not copy brand assets or protected artwork.

The dashboard views are:

- Monitor: real-time metrics, live incidents, and visitor stream.
- Incidents: incident list, detail view, redacted evidence, action runs.
- Visitors: visitor records.
- Content: monitored event payloads and scoring output.
- Models: owner-selected large model provider profiles and activation.
- AI Chat: direct conversation with the connected model provider using managed-site context.
- Account: password change.
- Audit: immutable operator and system actions.

## API Error Localization

API errors return both machine-readable and localized fields:

```json
{
  "ok": false,
  "code": "CAPTCHA_FAILED",
  "error": "captcha verification failed",
  "messageZh": "验证码校验失败。",
  "detailsZh": "验证码可能不存在、已过期、答案错误，或者连续错误次数过多后已被作废。",
  "hintZh": "请刷新验证码，重新选择正确答案后再提交登录请求。"
}
```

The frontend uses the Chinese fields when the selected language is `zh-CN`. Integrators can use `code` for stable programmatic handling.
