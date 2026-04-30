# SentinelAI Security Plugin - Development Log

## 2026-04-25

### Input Plan Synthesis

Two supplied plans were combined into one MVP direction:

- Preserve the agentic security plugin vision: website monitoring, LLM adapter, admin dashboard, host-agent check-ins, intercepted evidence, and configurable model providers.
- Apply the safer implementation constraints: rule-first detection, no arbitrary shell, least privilege, RBAC, audit trail, redaction, human approval for high-impact actions, and offline operation when the LLM is unavailable.

### Implementation Decisions

- Used Python stdlib only so the product runs without package installation or network access.
- Used SQLite for local persistence.
- Served a vanilla HTML/CSS/JS dashboard directly from the API server.
- Implemented an offline heuristic LLM adapter to keep the structured analysis contract active without external APIs.
- Implemented a simulated connector model for response actions.
- Made `capture_evidence` the only auto action that writes a local artifact.
- Kept `block_ip` as a local registry update rather than a firewall command.
- Kept high-impact actions dry-run unless `SENTINELAI_ENABLE_SYSTEM_ACTIONS=true`.

### Completed Components

- Project package and CLI entry point.
- HTTP API routes for login, status, sites, agents, events, incidents, action execution, providers, and audit logs.
- HTTP API routes for CAPTCHA issuance, password change, live monitor snapshots, monitored event content, visitor records, and provider activation.
- SQLite schema for operational state.
- SQLite schema additions for admin password hashes, CAPTCHA challenges, system settings, and visitor records.
- Event contract normalization.
- Sensitive payload redaction.
- Trust score and severity rules.
- Offline structured analysis adapter plus optional OpenAI-compatible/vLLM/Azure-style and Ollama model adapters.
- RBAC and action policy checks.
- Safe action validators and local evidence capture.
- Host-agent simulator.
- Bilingual English/Chinese browser dashboard with a tactical layout inspired by the referenced site, real-time monitored data, lists, event content, visitor records, model controls, password change, and CAPTCHA login.
- Unit and smoke tests.
- Usage, technology, and development documentation.

### Verification Commands

Run from the project root:

```powershell
python -m compileall sentinelai_plugin tests
node --check sentinelai_plugin\static\app.js
python -m unittest discover
```

Verification result on 2026-04-25:

```text
compileall: passed
node --check: passed
unittest: 4 tests passed
HTTP smoke: status endpoint passed, dashboard HTML passed
```

Additional update on 2026-04-26:

```text
Added bilingual UI, model API profile activation, optional external model adapters,
visitor records, monitored content feeds, live monitor snapshot API, advanced CAPTCHA
login, password change, and clean SQLite connection handling.
Verification: compileall passed, node --check passed, unittest 4 tests passed.
```

Run a demo server:

```powershell
python -m sentinelai_plugin --demo
```

Run the host-agent simulator:

```powershell
python -m sentinelai_plugin.agent --api http://127.0.0.1:8787 --token dev-ingest-token --send-demo-events
```

### Packaging

The release archive is produced as:

```text
sentinelai-security-plugin.zip
```

The archive contains source code, tests, static dashboard assets, and the three documentation files.
