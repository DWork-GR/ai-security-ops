# AI Security Ops (Integration-First MVP)

Integration-centric bachelor diploma project in cybersecurity.
The main value is SOC tooling integration (Snort/OpenVAS), not chat UX.

## Core Idea

The system ingests security signals, normalizes events, creates incidents,
and returns actionable recommendations.

Pipeline:
`Ingest -> Normalize -> Correlate -> Prioritize -> Recommend -> Track`

## Current Features

- `POST /chat` for analyst quick commands.
- `POST /integrations/snort/alerts` to ingest Snort alerts.
- `POST /integrations/openvas/scan` to start OpenVAS scan task.
- `GET /incidents` to query incident list.
- Incident correlation (24h dedup + severity escalation).
- CVE knowledge base queries via chat.

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
- Frontend rendering uses safe text output to avoid XSS.

## LLM Modes

- `LLM_PROVIDER=none`: no external LLM calls, fully offline backend logic.
- `LLM_PROVIDER=ollama`: local free model via Ollama API (`OLLAMA_BASE_URL`, `OLLAMA_MODEL`).
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
- Trigger OpenVAS scan task.
- Show incident records created by integrations.
- Show CVE lookup and mitigation guidance.
