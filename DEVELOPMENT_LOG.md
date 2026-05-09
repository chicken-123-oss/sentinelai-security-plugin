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

Additional update on 2026-04-28:

```text
Changed visitor recording to deduplicate repeated scan/polling results. Visitor rows
now keep firstSeen, lastSeen, and visitCount. Added /api/v1/visitors/record for
website middleware and reverse-proxy adapters. API errors now include detailed Chinese
message, details, and hint fields. Expanded usage documentation with API integration,
deployment, import, reverse proxy adaptation, admin-system adaptation, and model-provider
adaptation guidance.
Verification: compileall passed, node --check passed, unittest 4 tests passed.
```

Additional update on 2026-04-28:

```text
Added a managed-site backend entry surface: /managed-entry and
/api/v1/managed-site/summary expose compact plugin status, recent incidents, recent
visitors, connected agents, active model provider, and a localized redirect button for
the full SentinelAI console. Added the AI Chat dashboard tab and /api/v1/ai/chat,
with persisted conversation history in SQLite and replies from the active connected
model provider, using managed-site state as context and falling back offline when needed.
Expanded smoke tests and documentation for managed-site import, admin-portal adaptation,
and direct AI conversation.
Verification: compileall passed, node --check app.js passed, node --check managed-entry.js passed, unittest 4 tests passed.
```

## 2026-05-07

### Event Content Index Update

```text
Added /api/v1/events/index with score-level priority ranking, day-based indexing,
attacker-input extraction, and duplicate identical access collapse. The Content tab now
renders P0/P1/P2/P3 counts, grouped day sections, duplicateCount/firstSeen/lastSeen, and
escaped detailed attacker-entered content from redacted request payloads. Smoke coverage
now verifies duplicate event collapse, priority classification, day groups, and visible
attacker input summaries.
Verification: compileall passed, node --check app.js passed, node --check managed-entry.js passed, unittest 4 tests passed.
```

### Console Security Hardening

```text
Hardened the SentinelAI console itself: replaced wildcard CORS with same-origin default
plus SENTINELAI_ALLOWED_ORIGINS, added CSP/security/no-store headers, made dashboard
tokens session-only in the browser, removed managed-entry token loading from URL query
parameters, and documented SENTINELAI_FRAME_ANCESTORS for trusted embedding. Smoke tests
now verify CSP, no-referrer/nosniff headers, allowed and blocked CORS behavior, and the
absence of URL token parsing in managed-entry.js.
```

### Screenshot-Inspired Frontend Redesign

```text
Redesigned the console visual system to match the supplied reference image more closely.
Added dark mineral terrain layers, prism light beams, orbit rings, lime triangular shards,
clipped HUD panels, and circular mission progress nodes arranged around the real-time
monitoring surface.
Added local static mission-map.json to drive node labels, positions, progress totals, and
link beams. Overview map nodes now switch directly to Monitor, Incidents, Visitors,
Content, Models, and AI Chat. The implementation remains offline-capable and uses local
HTML, CSS, JavaScript, and JSON instead of external CDN libraries.
Verification: compileall passed, node --check app.js passed, node --check managed-entry.js passed, unittest 4 tests passed.
```

### Centered Monitor Map Adjustment

```text
Adjusted the overview layout to follow the later reference image: the real-time monitoring
title now sits in the central-left visual field, node text sizes were tightened to avoid
overlap, the top navigation was moved to the upper-right HUD row, and the clue unlock
reward strip was removed from HTML, JavaScript, CSS, and mission-map.json.
```

### AI API And Agent Framework Validation

```text
Hardened the connected AI chat path so the current operator question is always passed as
the latest model message, and stabilized agent message ordering with SQLite rowid tie
breaks. Added an automated OpenAI-compatible fake model server test that validates both
/api/v1/ai/chat and event-analysis ingestion with llmAvailable=true and fallbackUsed=false.
Also ran a live demo-server API integration check against a temporary local compatible
model endpoint; provider activation, agent check-in, AI chat, model-backed event analysis,
and /api/v1/status all returned successfully.
```

### China AI Provider Adaptation

```text
Added first-class provider types for DeepSeek, Zhipu GLM, and Kimi/Moonshot. Each provider
has UI presets, backend defaults, secret-reference defaults, OpenAI-compatible adapter
routing, and automated smoke coverage against a local compatible test model. The model
prompt now includes the SentinelAI scoring framework with identity, behavior, runtime,
and asset-impact layers, and model JSON parsing tolerates fenced Markdown JSON commonly
returned by chat models.
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
