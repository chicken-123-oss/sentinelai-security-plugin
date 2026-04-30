# SentinelAI Security Plugin

SentinelAI is a runnable MVP that combines the two supplied development plans into a safe web security monitoring plugin product.

It provides:

- A bilingual English/Chinese browser dashboard with a tactical high-contrast layout inspired by `https://ak.hypergryph.com/`.
- Real-time monitored data, incident lists, monitored event content, visitor records, model providers, account controls, and audit logs.
- A stdlib Python API server with SQLite storage.
- A rule-first trust scoring engine with an offline structured analyzer.
- Optional large-model API access through OpenAI-compatible/vLLM/Azure-style endpoints and Ollama, with automatic offline fallback.
- Advanced CAPTCHA login and owner password change.
- A constrained action catalog with approval gates and dry-run high-impact actions.
- A host-agent simulator for check-ins and demo event ingestion.

Run it:

```powershell
python -m sentinelai_plugin --demo
```

Open `http://127.0.0.1:8787` and sign in with `admin@example.com` / `sentinelai`.················································
