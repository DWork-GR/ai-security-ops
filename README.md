# AI Security Ops

Integration-first SOC assistant for a cybersecurity bachelor diploma project.

The project focuses on security operations workflows:
`Ingest -> Normalize -> Correlate -> Prioritize -> Recommend -> Track`

## What This Project Does

- Accepts events from integrations (Snort, OpenVAS/Nmap style scans).
- Correlates findings into incidents with ATT&CK enrichment.
- Tracks scan jobs, assets, errors, and outbound notification delivery.
- Provides analyst chat commands for quick SOC actions.
- Generates operational summaries for reports and demos.

## Architecture

Backend:
- `FastAPI` + `SQLAlchemy` + SQLite/PostgreSQL compatible config
- Modular API routers (`integrations`, `incidents`, `scans`, `assets`, `knowledge`, `errors`, `outbound`, `reports`, `stream`, `chat`)

Frontend:
- Static HTML/CSS/JS SOC console
- Chat workspace + queue status + discovered assets + live feed

Core security model:
- Integration auth via `X-API-Key`
- RBAC via `X-User-Key` (`analyst`, `manager`, `admin`)
- Sensitive values redacted in error pipeline

## Repository Layout

```text
backend/
  app/
    api/
    services/
    integrations/
    database/
frontend/
tests/
docs/
```

## Quick Start

1. Create and activate virtual environment.
2. Install dependencies:
```bash
pip install -r backend/requirements.txt
```
3. Create local config:
```bash
copy .env.example .env
```
4. Set strong secrets in `.env`:
- `INTEGRATION_API_KEY`
- `RBAC_KEYS`
5. Run API:
```bash
uvicorn app.main:app --reload --app-dir backend
```
6. Open frontend with a local static server and load `frontend/index.html`.
7. Run tests:
```bash
python -m pytest -q
```

## Configuration

Important env flags:

- `RBAC_ENABLED=true`
- `INTEGRATION_AUTH_REQUIRED=true`
- `CHAT_AUTH_REQUIRED=true`
- `STREAM_ALLOW_QUERY_USER_KEY=false`
- `CORS_ORIGINS=http://127.0.0.1:5500` (set your real origin in production)
- `LLM_PROVIDER=none|ollama|gemini`

Recommended:
- Keep `LLM_PROVIDER=none` for fully offline demo mode.
- Use `ollama` for local free LLM integration.

## Authentication and Authorization

Integration endpoints:
- Protected by `X-API-Key` when `INTEGRATION_AUTH_REQUIRED=true`.
- Fail-closed if auth is enabled but server key is not configured.

RBAC endpoints:
- Use `X-User-Key` mapped by `RBAC_KEYS`.
- Role scopes:
  - `analyst`: read and analyst operations
  - `manager`: management operations, reports, outbound stats
  - `admin`: full access

Chat:
- `POST /chat` requires `X-User-Key` when `CHAT_AUTH_REQUIRED=true`.

Stream:
- `GET /stream/soc-live` requires `X-User-Key` header by default.
- Query auth (`user_key`) is disabled by default.

## Main API Surface

Integrations:
- `POST /integrations/snort/alerts`
- `POST /integrations/openvas/scan`
- `POST /integrations/openvas/scan/active`
- `POST /integrations/nmap/scan/active`

Scans:
- `POST /scans/jobs`
- `GET /scans/jobs`
- `GET /scans/jobs/{id}`
- `POST /scans/jobs/{id}/run`

Incidents and SOC metrics:
- `GET /incidents`
- `GET /incidents/stats/summary`
- `PATCH /incidents/{id}/status`
- `GET /incidents/{id}/audit`

Knowledge base:
- `GET /knowledge/cves/search`
- `GET /knowledge/cves/{cve_id}`
- `POST /knowledge/cves/seed/real-world`
- `POST /knowledge/cves/import/nvd`

Ops visibility:
- `GET /assets/discovered`
- `GET /errors`
- `GET /errors/stats/summary`
- `GET /outbound/events`
- `GET /outbound/events/stats/summary`
- `GET /stream/soc-live`

Reports:
- `GET /reports/operations`
- `GET /reports/operations/markdown`

## Chat Commands (Examples)

- `help`
- `full check 127.0.0.1`
- `scan 10.0.0.5`
- `show incidents`
- `incident stats`
- `show critical cves`
- `search cve apache`
- `show errors`
- `error stats`
- `analyze threats`
- `system status`
- `roadmap`

## Security Checklist

- Do not commit real `.env` values.
- Rotate secrets if they were ever committed.
- Restrict CORS origins in production.
- Use long random keys for `INTEGRATION_API_KEY` and `RBAC_KEYS`.
- Keep `STREAM_ALLOW_QUERY_USER_KEY=false`.
- Keep TLS and reverse-proxy auth in real deployment.
- Review `/errors` access policy before public exposure.

## LLM Modes

- `LLM_PROVIDER=none`: offline logic only.
- `LLM_PROVIDER=ollama`: local model endpoint (`OLLAMA_BASE_URL`, `OLLAMA_MODEL`).
- `LLM_PROVIDER=gemini`: cloud model (`GEMINI_API_KEY` required).

Ollama quick example:

```bash
ollama pull llama3.2:3b
```

`.env`:
- `LLM_PROVIDER=ollama`
- `OLLAMA_MODEL=llama3.2:3b`

## Demo Flow (5-7 Minutes)

1. Seed threat pack: `POST /knowledge/cves/seed/real-world`.
2. Send sample Snort alert.
3. Run active scan on test host.
4. Open incidents and incident stats.
5. Show discovered assets and scan queue.
6. Show errors/outbound stats.
7. Export markdown operations report.

## Testing

Run:

```bash
python -m pytest -q
```

Acceptance tests cover:
- auth guards
- RBAC restrictions
- scan job lifecycle
- stream access behavior
- outbound retry/idempotency
- incident/error/report flows
