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

## 4. Dashboard Workflow

1. Open `http://127.0.0.1:8787`.
2. Pick English or Chinese from the header language toggle.
3. Complete the advanced CAPTCHA challenge and sign in as the owner.
4. Review the Monitor page for real-time incident counts, live lists, visitor records, active model, and action mode.
5. Open Incidents to inspect rule matches, redacted evidence, structured analysis, and recommended action runs.
6. Open Content to view monitored event payloads after redaction.
7. Open Visitors to inspect recent request paths, methods, IPs, user agents, and timestamps.
8. Use Approve or Reject to record the human decision.
9. Run approved or policy-ready actions from the incident detail panel.
10. Check Models, Account, and Audit for model-provider selection, password changes, and operator history.

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

## 8. Host-Agent Simulator

With the server running, send a check-in and demo events:

```powershell
python -m sentinelai_plugin.agent --api http://127.0.0.1:8787 --token dev-ingest-token --send-demo-events
```

The simulator demonstrates the intended host-agent contract without requiring SSH, root privileges, Docker, or external security tools.

## 9. Test The Product

```powershell
python -m compileall sentinelai_plugin tests
node --check sentinelai_plugin\static\app.js
python -m unittest discover
```

The tests cover deterministic scoring, redaction and incident storage, login, event ingestion, incident listing, and safe evidence capture.

## 10. Production Notes

- Replace all default tokens and passwords.
- Put the API behind TLS and a real authentication boundary.
- Connect `block_ip`, `disable_account`, `quarantine_file`, and similar actions to audited production connectors instead of granting arbitrary shell access.
- Keep external LLM providers optional. Detection continues through local rules when the model is unavailable.
- Use a proper secret manager for server bootstrap credentials. The current MVP stores only provider secret references, not raw keys.
