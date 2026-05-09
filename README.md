# SentinelAI Security Plugin

SentinelAI is a runnable MVP that combines the two supplied development plans into a safe web security monitoring plugin product.

It provides:

- A bilingual English/Chinese browser dashboard with a tactical clue-map layout inspired by the supplied reference screenshot: dark mineral terrain, prism beams, circular progress nodes, lime unlock accents, clipped HUD panels, and node-click navigation.
- Real-time monitored data, incident lists, monitored event content, visitor records, model providers, account controls, and audit logs.
- Event priority ranking by score level, with content indexing by day and duplicate identical accesses collapsed into one indexed row.
- Detailed event content display for attacker-entered request bodies, query strings, commands, and other redacted payload fields.
- Visitor records are deduplicated; repeated scanner hits update `lastSeen` and `visitCount`.
- A managed-site backend entry page at `/managed-entry`, backed by `/api/v1/managed-site/summary`, for embedding SentinelAI status inside an existing admin portal with a redirect button to the full console.
- A connected AI conversation tab and `/api/v1/ai/chat` API for talking to the active large-model provider with current site, incident, visitor, and agent context.
- A stdlib Python API server with SQLite storage.
- A rule-first trust scoring engine with an offline structured analyzer.
- Optional large-model API access through OpenAI-compatible/vLLM/Azure-style endpoints, DeepSeek, Zhipu GLM, Kimi/Moonshot, and Ollama, with automatic offline fallback.
- Advanced CAPTCHA login and owner password change.
- Detailed API errors include Chinese `messageZh`, `detailsZh`, and `hintZh` fields.
- Console hardening: same-origin CORS by default, CSP/security headers, no URL token loading, and session-only browser token storage.
- A constrained action catalog with approval gates and dry-run high-impact actions.
- A host-agent simulator for check-ins and demo event ingestion.

Run it:

```powershell
python -m sentinelai_plugin --demo
```

Open `http://127.0.0.1:8787` and sign in with `admin@example.com` / `sentinelai`.
