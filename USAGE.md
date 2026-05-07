# SentinelAI Security Plugin - Usage Instructions

## 1. Requirements

- Python 3.10 or newer.
- No third-party Python packages are required.
- A writable directory for SQLite data, evidence bundles, and local action registries.

## 2. Start The Product

From the project root:

```powershell
python -m sentinelai_plugin --demo
```

The server starts on:

```text
http://127.0.0.1:8787
```

Default local credentials:

```text
Email:    admin@example.com
Password: sentinelai
```

Change these before any shared or production-like use:

```powershell
$env:SENTINELAI_ADMIN_EMAIL="owner@example.com"
$env:SENTINELAI_ADMIN_PASSWORD="use-a-strong-password"
$env:SENTINELAI_ADMIN_TOKEN="replace-dev-owner-token"
$env:SENTINELAI_INGEST_TOKEN="replace-dev-ingest-token"
python -m sentinelai_plugin --demo
```

## 3. Runtime Options

```powershell
python -m sentinelai_plugin --host 127.0.0.1 --port 8787 --db data\sentinelai.sqlite3 --data-dir data --demo
```

Environment variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `SENTINELAI_HOST` | Bind host | `127.0.0.1` |
| `SENTINELAI_PORT` | Bind port | `8787` |
| `SENTINELAI_DB_PATH` | SQLite database path | `data/sentinelai.sqlite3` |
| `SENTINELAI_DATA_DIR` | Evidence and action data path | `data` |
| `SENTINELAI_ADMIN_EMAIL` | Owner login email | `admin@example.com` |
| `SENTINELAI_ADMIN_PASSWORD` | Owner login password | `sentinelai` |
| `SENTINELAI_ADMIN_TOKEN` | Owner API bearer token | `dev-owner-token` |
| `SENTINELAI_AUDITOR_TOKEN` | Read-only API bearer token | `dev-auditor-token` |
| `SENTINELAI_INGEST_TOKEN` | Agent/event ingestion token | `dev-ingest-token` |
| `SENTINELAI_ENABLE_SYSTEM_ACTIONS` | Enables local high-impact actions when set to `true` | disabled |
| `SENTINELAI_ALLOWED_PATHS` | Path allowlist for quarantine actions | data directory only |
| `SENTINELAI_ALLOWED_SERVICES` | Comma-separated service names for restart actions | empty |
| `SENTINELAI_ALLOWED_ORIGINS` | Comma-separated extra browser origins allowed by CORS | same-origin only |
| `SENTINELAI_FRAME_ANCESTORS` | CSP `frame-ancestors` value for managed-entry embedding | `'self'` |

## 4. Dashboard Workflow

1. Open `http://127.0.0.1:8787`.
2. Pick English or Chinese from the header language toggle.
3. Complete the advanced CAPTCHA challenge and sign in as the owner.
4. Review the Monitor page for real-time incident counts, live lists, visitor records, active model, and action mode.
5. Open Incidents to inspect rule matches, redacted evidence, structured analysis, and recommended action runs.
6. Open Content to view the event priority index. Events are grouped by day, ranked by score level, and duplicate identical accesses are collapsed into one row with `duplicateCount`.
7. Expand event details to inspect attacker-entered content such as request body, query string, command, path, and other redacted payload fields.
8. Open Visitors to inspect recent request paths, methods, IPs, user agents, and timestamps.
9. Use Approve or Reject to record the human decision.
10. Run approved or policy-ready actions from the incident detail panel.
11. Open AI Chat to talk directly with the connected large-model provider about status, incidents, visitors, or model access. The managed-site agent is used as context.
12. Check Models, Account, and Audit for model-provider selection, password changes, and operator history.

High-impact actions are dry-run by default. `capture_evidence` writes a redacted JSON artifact under `data/evidence`. `block_ip` records the IP under `data/blocked_ips.json` as a connector-safe simulation.

## 5. Large Model API Access

The product ships with an offline analyzer, then lets the owner add and activate large-model providers independently from the UI.

Supported provider profiles:

- `offline_heuristic`
- `openai`
- `azure_openai`
- `openai_compatible`
- `vllm`
- `ollama`
- `anthropic` and `gemini` as stored provider profiles for future connector expansion

For OpenAI-compatible/vLLM/Azure-style providers, set:

- Provider name
- Provider type
- Endpoint, for example `https://api.example.com/v1`
- Model, for example `gpt-4.1-mini` or a local vLLM model name
- Secret reference, for example `SENTINELAI_OPENAI_KEY`

The secret reference is read from the environment. Raw API keys are not stored in SQLite:

```powershell
$env:SENTINELAI_OPENAI_KEY="sk-..."
python -m sentinelai_plugin --demo
```

For Ollama, use an endpoint such as:

```text
http://127.0.0.1:11434
```

If a configured model is unreachable or returns invalid JSON, monitoring falls back to the offline analyzer and continues running.

## 6. Password Change

After login, open Account and submit:

- Current password
- New password with at least 10 characters, including a digit and a letter

The new password is stored as a PBKDF2 hash with a random salt.

## 7. API Examples

Fetch a CAPTCHA:

```powershell
Invoke-RestMethod -Method Get -Uri http://127.0.0.1:8787/api/v1/auth/captcha
```

Login after solving the CAPTCHA:

```powershell
$login = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8787/api/v1/auth/login `
  -ContentType "application/json" `
  -Body '{"email":"admin@example.com","password":"sentinelai","captchaId":"cap_xxx","captchaAnswer":"123"}'
$token = $login.token
```

Ingest a suspicious event:

```powershell
$event = @{
  source = "nginx"
  category = "request"
  trustLabel = "low"
  severityHint = "high"
  actor = @{ type = "ip"; id = "203.0.113.10"; ip = "203.0.113.10" }
  asset = @{ kind = "site"; id = "/login" }
  payload = @{ body = "username=admin' OR '1'='1" }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8787/api/v1/events/ingest `
  -Headers @{ Authorization = "Bearer dev-ingest-token" } `
  -ContentType "application/json" `
  -Body $event
```

List incidents:

```powershell
Invoke-RestMethod -Method Get -Uri http://127.0.0.1:8787/api/v1/incidents `
  -Headers @{ Authorization = "Bearer $token" }
```

Get the live monitor snapshot:

```powershell
Invoke-RestMethod -Method Get -Uri http://127.0.0.1:8787/api/v1/monitor/live `
  -Headers @{ Authorization = "Bearer $token" }
```

Get the indexed event content feed:

```powershell
Invoke-RestMethod -Method Get -Uri http://127.0.0.1:8787/api/v1/events/index `
  -Headers @{ Authorization = "Bearer $token" }
```

Load the managed-site backend entry summary:

```powershell
Invoke-RestMethod -Method Get -Uri http://127.0.0.1:8787/api/v1/managed-site/summary `
  -Headers @{ Authorization = "Bearer dev-ingest-token" }
```

Ask the connected AI a question:

```powershell
$chat = @{
  agentId = "agent_local"
  message = "Please report current status and latest incident."
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8787/api/v1/ai/chat `
  -Headers @{ Authorization = "Bearer $token" } `
  -ContentType "application/json" `
  -Body $chat
```

Record a visitor from your website middleware or reverse proxy adapter:

```powershell
$visitor = @{
  ip = "203.0.113.77"
  userAgent = "Mozilla/5.0"
  path = "/pricing"
  method = "GET"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8787/api/v1/visitors/record `
  -Headers @{ Authorization = "Bearer dev-ingest-token" } `
  -ContentType "application/json" `
  -Body $visitor
```

Duplicate visitor records are not inserted repeatedly. SentinelAI fingerprints `ip + userAgent + path + method`; repeated hits update `lastSeen` and `visitCount`.

## 8. API Integration Guide

### Authentication

There are two token classes:

- Owner/operator APIs use the token returned by `POST /api/v1/auth/login`.
- Collector, middleware, and host-agent ingestion APIs use `SENTINELAI_INGEST_TOKEN`.

Every authenticated request must include:

```text
Authorization: Bearer <token>
Content-Type: application/json
```

### Event Ingestion Contract

Send security observations to:

```text
POST /api/v1/events/ingest
```

Minimum useful payload:

```json
{
  "source": "nginx",
  "category": "request",
  "trustLabel": "low",
  "severityHint": "high",
  "actor": { "type": "ip", "id": "203.0.113.10", "ip": "203.0.113.10" },
  "asset": { "kind": "site", "id": "/login" },
  "labels": ["admin_panel"],
  "payload": { "method": "POST", "path": "/login", "body": "username=admin' OR '1'='1" }
}
```

Recommended adapter mapping:

| Source system | SentinelAI field | Notes |
| --- | --- | --- |
| Web server access log | `source=nginx|apache`, `category=request` | Put URL, method, status, and request excerpt in `payload`. |
| Application auth log | `source=auth`, `category=login` | Put user id, source IP, failure count, MFA state in `actor` and `payload`. |
| File watcher | `source=file`, `category=file_change|file_access` | Put changed path in `asset.id`; never send raw secrets. |
| Process watcher | `source=process`, `category=proc_spawn` | Put process name in `asset.id`, PID/command in `payload`. |
| Threat feed | `source=threat_feed`, `category=ioc_match` | Put matched IOC and feed name in `labels`/`payload`. |

### Event Content Index

Use the indexed feed when building an operations console:

```text
GET /api/v1/events/index?limit=160
```

The endpoint returns:

```json
{
  "priorityCounts": { "critical": 0, "high": 1, "medium": 0, "low": 0 },
  "rawEventCount": 2,
  "uniqueEventCount": 1,
  "duplicatesCollapsed": 1,
  "days": [
    {
      "day": "2026-05-07",
      "count": 1,
      "items": [
        {
          "priority": { "rank": 1, "level": "high", "label": "P1 High" },
          "duplicateCount": 2,
          "firstSeen": "2026-05-07T10:00:00Z",
          "lastSeen": "2026-05-07T10:03:00Z",
          "attackerInput": {
            "summary": "body=username=admin' OR '1'='1",
            "fields": { "body": "username=admin' OR '1'='1" }
          }
        }
      ]
    }
  ]
}
```

Priority levels are derived from `trustScore`, `riskScore`, and severity:

| Level | Meaning |
| --- | --- |
| `critical` / `P0` | trust 0-29, risk 70-100, or critical severity |
| `high` / `P1` | trust 30-59, risk 40-69, or high severity |
| `medium` / `P2` | trust 60-89, risk 10-39, or medium severity |
| `low` / `P3` | trust 90-100 and low risk |

Deduplication uses source, category, actor IP/id, asset path, request method, path, query, and attacker-entered body/command. The stored event is still escaped in the browser and redacted before persistence, so operators can inspect malicious input without exposing passwords, cookies, bearer tokens, or secrets.

### Visitor Record Contract

Send real visitor records to:

```text
POST /api/v1/visitors/record
```

Payload:

```json
{
  "ip": "203.0.113.77",
  "userAgent": "Mozilla/5.0",
  "path": "/pricing",
  "method": "GET"
}
```

This interface is intentionally separate from security event ingestion. It is for visitor visibility, not threat scoring. Repeated identical visits update `visitCount` and `lastSeen`, so scanner refreshes and dashboard polling do not create duplicate rows.

### Managed Website Backend Entry

SentinelAI exposes an embeddable backend entry page for an existing managed website admin portal:

```text
GET /managed-entry
```

The page requires the operator to paste a token or reuse a same-tab session token. It no longer reads bearer tokens from URL query parameters, because URLs can leak through logs, screenshots, browser history, and referrers. It displays compact status, incident, visitor, agent, and model information, then provides an "Open Console" redirect button to the full plugin dashboard.

For safer production deployments, prefer a server-side admin-portal proxy instead of putting tokens into URLs:

1. Your managed website backend stores `SENTINELAI_INGEST_TOKEN` or an auditor token in its server environment.
2. The admin portal calls `GET /api/v1/managed-site/summary` from server-side code.
3. The portal renders the summary in its own backend page.
4. The redirect button points authorized operators to the SentinelAI console URL returned as `consoleUrl`.

Summary endpoint:

```text
GET /api/v1/managed-site/summary
Authorization: Bearer <admin | auditor | ingest token>
```

The response includes:

```json
{
  "status": { "counts": { "incidents": 1, "visitors": 3, "agents": 1 } },
  "activeProvider": { "name": "Offline Heuristic Analyzer", "model": "sentinelai-offline-v1" },
  "incidents": [],
  "visitors": [],
  "agents": [],
  "consoleUrl": "http://127.0.0.1:8787/",
  "managedEntryUrl": "http://127.0.0.1:8787/managed-entry",
  "redirectButton": { "label": "Open SentinelAI Console", "labelZh": "打开 SentinelAI 控制台", "url": "http://127.0.0.1:8787/" }
}
```

### Connected AI Conversation Contract

Register or check in the managed website agent first:

```text
POST /api/v1/agents/register
POST /api/v1/agents/check-in
Authorization: Bearer <ingest token>
```

Then use the dashboard AI Chat tab or call:

```text
POST /api/v1/ai/chat
Authorization: Bearer <admin token>
```

Payload:

```json
{
  "agentId": "agent_local",
  "message": "请汇报当前状态和最新事件"
}
```

The response stores both the operator message and the connected AI reply. SentinelAI sends recent monitored context to the currently active model provider. If the model provider is offline or not configured, the offline analyzer returns a safe fallback answer instead of failing the request:

```json
{
  "ok": true,
  "agentId": "agent_local",
  "message": { "role": "user", "message": "..." },
  "reply": { "role": "agent", "message": "..." },
  "provider": "Offline Heuristic Analyzer",
  "llmAvailable": false,
  "fallbackUsed": true,
  "items": []
}
```

Conversation history is available through:

```text
GET /api/v1/ai/chat?agentId=agent_local
Authorization: Bearer <admin | auditor token>
```

The older `/api/v1/agent/chat` path remains as a compatibility alias, but new integrations should use `/api/v1/ai/chat`.

### Error Response Shape

Errors include English and detailed Chinese fields:

```json
{
  "ok": false,
  "code": "AUTH_REQUIRED",
  "error": "missing or invalid bearer token",
  "messageZh": "认证失败：缺少或无效的 Bearer Token。",
  "detailsZh": "该接口需要在请求头中提供 Authorization: Bearer <token>。",
  "hintZh": "登录后使用返回的管理员 token；采集端接口请使用 SENTINELAI_INGEST_TOKEN。"
}
```

Frontend integrations should display `messageZh + detailsZh + hintZh` when the UI language is Chinese.

## 9. Deployment, Import, And Adaptation

### Local Deployment

1. Extract `sentinelai-security-plugin.zip`.
2. Enter the project directory.
3. Set strong secrets:

```powershell
$env:SENTINELAI_ADMIN_EMAIL="owner@example.com"
$env:SENTINELAI_ADMIN_PASSWORD="change-me-now-123"
$env:SENTINELAI_ADMIN_TOKEN="replace-owner-token"
$env:SENTINELAI_INGEST_TOKEN="replace-ingest-token"
$env:SENTINELAI_DATA_DIR="C:\sentinelai\data"
$env:SENTINELAI_DB_PATH="C:\sentinelai\data\sentinelai.sqlite3"
python -m sentinelai_plugin --host 127.0.0.1 --port 8787
```

4. Put a reverse proxy with TLS in front of the service for shared environments.
5. Restrict access to the console path with your network firewall, VPN, or SSO gateway.

### Import Into A Python Web App

Use SentinelAI as a local library from the project root:

```python
from sentinelai_plugin.pipeline import process_event
from sentinelai_plugin.storage import Storage

storage = Storage("data/sentinelai.sqlite3")
storage.init()
storage.ensure_defaults("owner@example.com", "initial-password-123")

incident = process_event(storage, {
    "source": "app",
    "category": "request",
    "trustLabel": "low",
    "severityHint": "high",
    "actor": {"type": "ip", "id": client_ip, "ip": client_ip},
    "asset": {"kind": "site", "id": request_path},
    "payload": {"method": method, "path": request_path, "body": redacted_body}
}, actor="app-middleware")
```

### Reverse Proxy Adaptation

For Nginx, Apache, CDN workers, or WAF adapters:

1. Parse the incoming request metadata.
2. Redact cookies, authorization headers, passwords, and tokens before sending payloads.
3. Send a visitor record to `/api/v1/visitors/record`.
4. Send only suspicious observations to `/api/v1/events/ingest`, or send all events if you want centralized scoring.
5. Keep the ingest token outside the public frontend; use server-side middleware only.

### Existing Admin System Adaptation

If you already have an admin portal:

1. Keep SentinelAI behind the same trusted network boundary.
2. Replace the default token handling with your SSO/session gateway at the reverse proxy layer.
3. Continue using SentinelAI RBAC internally for owner-only model and policy changes.
4. Add a backend menu entry such as "Security Monitor" or "SentinelAI" in the managed website admin portal.
5. For the fastest integration, link that menu entry to `/managed-entry` or render it in a trusted iframe.
6. For a stricter integration, call `/api/v1/managed-site/summary` from the admin backend, render the returned counts/lists in your own template, and use `redirectButton.url` for the full-console button.
7. Keep `SENTINELAI_INGEST_TOKEN` and auditor tokens on the server side; do not put long-lived tokens into public JavaScript.
8. Map your admin roles to SentinelAI tokens: owner token for configuration, auditor token for read-only display, ingest token only for server-side collection and summary widgets.
9. Keep password-change enabled for standalone mode, or hide the Account tab if your SSO owns password lifecycle.

### Model Provider Adaptation

For hosted OpenAI-compatible APIs:

1. Set the provider endpoint, model, and secret reference in the Models tab.
2. Export the real key in the server environment using the same secret reference name.
3. Activate the provider.
4. Ingest a known test event.
5. Check incident analysis for `llmAvailable=true`; if unavailable, inspect `fallbackReason`.

For local Ollama:

1. Start Ollama and pull a JSON-capable model.
2. Add provider type `ollama`.
3. Use endpoint `http://127.0.0.1:11434`.
4. Activate the provider.

## 10. Host-Agent Simulator

With the server running, send a check-in and demo events:

```powershell
python -m sentinelai_plugin.agent --api http://127.0.0.1:8787 --token dev-ingest-token --send-demo-events
```

The simulator demonstrates the intended host-agent contract without requiring SSH, root privileges, Docker, or external security tools.

## 11. Test The Product

```powershell
python -m compileall sentinelai_plugin tests
node --check sentinelai_plugin\static\app.js
node --check sentinelai_plugin\static\managed-entry.js
python -m unittest discover
```

The tests cover deterministic scoring, redaction and incident storage, login, event ingestion, incident listing, safe evidence capture, visitor deduplication, managed-site summary, managed-entry serving, and agent chat history.

## 12. Production Notes

- Replace all default tokens and passwords.
- Put the API behind TLS and a real authentication boundary.
- Browser CORS is same-origin by default. Add trusted admin portal origins with `SENTINELAI_ALLOWED_ORIGINS`, not `*`.
- The console sends CSP, `nosniff`, no-referrer, permissions, and frame-ancestor headers. Set `SENTINELAI_FRAME_ANCESTORS` only when a trusted admin portal must embed `/managed-entry`.
- Dashboard bearer tokens are kept in `sessionStorage`, not persistent `localStorage`; managed-entry does not read tokens from URL query parameters.
- Connect `block_ip`, `disable_account`, `quarantine_file`, and similar actions to audited production connectors instead of granting arbitrary shell access.
- Keep external LLM providers optional. Detection continues through local rules when the model is unavailable.
- Use a proper secret manager for server bootstrap credentials. The current MVP stores only provider secret references, not raw keys.
- Keep visitor recording on the server side only. Do not expose `SENTINELAI_INGEST_TOKEN` in browser JavaScript.
