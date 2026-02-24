# AI Security Ops (Integration-First MVP)

Integration-centric bachelor diploma project in cybersecurity.
The main value is SOC tooling integration (Snort/OpenVAS), not chat UX.

## Core Idea

The system ingests security signals, normalizes events, creates incidents,
and returns actionable recommendations.

Pipeline:
`Ingest -> Normalize -> Correlate -> Prioritize -> Recommend -> Track`

## User-Friendly Chat Mode

For non-technical users, use chat as a single control panel:
- `допомога`
- `повна перевірка <ip>`
- `скан <ip>`
- `покажи інциденти`
- `статистика інцидентів`
- `покажи критичні cve`
- `пошук cve <ключове_слово>`
- `покажи помилки`
- `статистика помилок`

## Current Features

- `POST /chat` for analyst quick commands.
- `POST /integrations/snort/alerts` to ingest Snort alerts.
- `POST /integrations/openvas/scan` to start OpenVAS scan task.
- `POST /integrations/openvas/scan/active` to run active TCP scan with findings.
- `GET /incidents` to query incident list.
- `GET /incidents/stats/summary` for SOC KPI snapshot.
- `PATCH /incidents/{id}/status` for incident lifecycle workflow.
- `GET /incidents/{id}/audit` for status/audit history.
- `GET /knowledge/cves/search` for CVE filtering by query/severity/CVSS.
- `GET /errors` and `GET /errors/stats/summary` for operational error search.
- `GET /reports/operations` for bilingual operations report (EN/UK).
- `GET /reports/operations/markdown` for export-ready Markdown report.
- Incident correlation (24h dedup + severity escalation).
- CVE knowledge base queries via chat.
- Error event deduplication with fingerprints and occurrence counters.

## Setup

1. Create and activate a virtual environment.
2. Install backend dependencies:
   - `pip install -r backend/requirements.txt`
3. Copy env template and set real secrets:
   - `.env.example -> .env`
   - For no external AI usage set `LLM_PROVIDER=none`.
   - For free local AI set `LLM_PROVIDER=ollama` and run Ollama locally.
4. Run API:
   - `uvicorn app.main:app --reload --app-dir backend`
5. Open frontend:
   - `frontend/index.html` using local static server.
6. Run tests:
   - `python -m pytest -q`

## Security Notes

- Do not commit real `.env` values.
- Restrict `CORS_ORIGINS` in production.
- Protect integration endpoints with `INTEGRATION_API_KEY` and `X-API-Key` header.
- Optional RBAC for analyst/manager/admin using `X-User-Key` header.
- Frontend rendering uses safe text output to avoid XSS.

## LLM Modes

- `LLM_PROVIDER=none`: no external LLM calls, fully offline backend logic.
- `LLM_PROVIDER=ollama`: local free model via Ollama API (`OLLAMA_BASE_URL`, `OLLAMA_MODEL`).
  - Optional token for remote endpoint: `OLLAMA_API_KEY`.
- `LLM_PROVIDER=gemini`: cloud Gemini API with `GEMINI_API_KEY`.

### Ollama Quick Start (free local)

1. Install Ollama and run it locally (default API: `http://localhost:11434`).
2. Pull a model:
   - `ollama pull llama3.2:3b`
3. In `.env` set:
   - `LLM_PROVIDER=ollama`
   - `OLLAMA_MODEL=llama3.2:3b`
4. Restart backend.

## Demo Checklist

- Ingest sample Snort alert.
- Trigger OpenVAS active scan and inspect findings.
- Show incident records created by integrations.
- Show CVE lookup and mitigation guidance.
- Show error search/statistics endpoint after forced integration failure.
