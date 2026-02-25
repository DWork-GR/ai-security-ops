## API Contracts

Base URL: `/`

## 1) Chat Endpoint

### `POST /chat`
Request:
```json
{
  "message": "scan 127.0.0.1"
}
```

Response variants:
- `{"type":"text","message":"..."}`
- `{"type":"cves","cves":[...]}`

Supported commands include:
- `show cves`
- `show critical cves`
- `search cve apache`
- `scan 127.0.0.1`
- `show incidents`
- `incident stats`
- `show errors`
- `error stats`
- `analyze threats`

## 2) Integration Endpoints

Headers:
- `X-API-Key: <shared_key>` (required when `INTEGRATION_API_KEY` is configured)

### `POST /integrations/snort/alerts`
Request:
```json
{
  "alerts": [
    {
      "message": "[**] SQL Injection Attempt [**]",
      "priority": 1,
      "src_ip": "192.168.1.10",
      "dst_ip": "10.0.0.5",
      "detected_at": "2026-02-24T12:00:00Z"
    }
  ]
}
```

Response:
```json
{
  "accepted": 1,
  "incidents_created": 1,
  "incidents_updated": 0
}
```

### `POST /integrations/openvas/scan`
Request:
```json
{
  "target": "10.0.0.5"
}
```

Response:
```json
{
  "task_id": "uuid",
  "target": "10.0.0.5",
  "status": "running"
}
```

### `POST /integrations/openvas/scan/active`
Request:
```json
{
  "target": "127.0.0.1",
  "ports": [22, 80, 443],
  "timeout_ms": 120
}
```

Response:
```json
{
  "task_id": "uuid",
  "scanner": "openvas",
  "discovery_engine": "nmap|socket-fallback",
  "target": "127.0.0.1",
  "status": "completed",
  "scan_profile": "tcp-custom",
  "scanned_ports": 3,
  "open_ports": [80],
  "duration_ms": 64,
  "findings": [
    {
      "port": 80,
      "protocol": "tcp",
      "service": "http",
      "severity": "CRITICAL",
      "risk_score": 95,
      "cvss_max": 10,
      "cve_references": ["CVE-2021-44228"],
      "summary_en": "...",
      "summary_uk": "..."
    }
  ],
  "incidents_created": 1,
  "incidents_updated": 0,
  "baseline_scan_task_id": "uuid|null",
  "new_open_ports": [80],
  "closed_open_ports": []
}
```

### `POST /integrations/nmap/scan/active`
Request:
```json
{
  "target": "127.0.0.1",
  "ports": [22, 80, 443],
  "timeout_ms": 120
}
```

Response:
```json
{
  "task_id": "uuid",
  "scanner": "nmap",
  "discovery_engine": "nmap|socket-fallback",
  "target": "127.0.0.1",
  "status": "completed",
  "scan_profile": "nmap-tcp-custom",
  "scanned_ports": 3,
  "open_ports": [80],
  "duration_ms": 64,
  "findings": [],
  "incidents_created": 1,
  "incidents_updated": 0,
  "baseline_scan_task_id": "uuid|null",
  "new_open_ports": [80],
  "closed_open_ports": []
}
```

## 3) Scan Job Endpoints

### `POST /scans/jobs`
Request:
```json
{
  "target_ip": "127.0.0.1",
  "scan_type": "quick"
}
```

Response:
```json
{
  "id": "uuid",
  "target_ip": "127.0.0.1",
  "scan_type": "quick",
  "status": "queued",
  "attempts": 0,
  "result_summary": null,
  "last_error": null,
  "created_at": "2026-02-24T12:00:00Z",
  "started_at": null,
  "finished_at": null
}
```

### `GET /scans/jobs`
Filters:
- `limit`, `status`, `scan_type`, `target_ip`

### `GET /scans/jobs/{job_id}`
Returns one scan job.

### `POST /scans/jobs/{job_id}/run`
Manager/admin endpoint. Forces immediate execution for queued/failed job.

## 4) Incident Endpoints

Headers for incident/report/knowledge/error/outbound endpoints when RBAC enabled:
- `X-User-Key: <analyst|manager|admin key>`

### `GET /incidents`
Filters:
- `limit`, `source`, `severity`, `status`, `search`, `min_risk`, `attack_tactic`, `attack_technique`, `date_from`, `date_to`

Each incident item also includes ATT&CK enrichment:
- `attack_tactic`
- `attack_technique_id`
- `attack_technique_name`
- `attack_confidence`

### `PATCH /incidents/{incident_id}/status`
Request:
```json
{
  "status": "triaged"
}
```

### `GET /incidents/{incident_id}/audit`
Response includes status transitions and actor role.

### `GET /incidents/stats/summary`
Returns operational KPI counters by status/severity/source.

## 5) Knowledge Base Endpoints

### `GET /knowledge/cves/search`
Filters:
- `q`, `severity`, `min_cvss`, `limit`

Response:
```json
{
  "total": 2,
  "items": [
    {
      "cve_id": "CVE-2021-44228",
      "cvss": 10,
      "severity": "CRITICAL",
      "description": "...",
      "mitigation": "..."
    }
  ]
}
```

### `GET /knowledge/cves/{cve_id}`
Returns one CVE record.

### `POST /knowledge/cves/seed/real-world`
Manager/admin endpoint to import curated real-world CVEs.

Response:
```json
{
  "imported_total": 46,
  "created": 26,
  "updated": 20,
  "source": "real-world-curated-pack"
}
```

## 6) Asset Inventory Endpoints

### `GET /assets`
Filters:
- `limit`, `criticality`, `environment`, `search`

### `GET /assets/discovered`
Returns discovered device inventory view (last seen + latest scan/open ports).

Response:
```json
{
  "items": [
    {
      "ip": "127.0.0.1",
      "hostname": null,
      "criticality": "MEDIUM",
      "environment": "unknown",
      "last_seen_at": "2026-02-24T12:00:00Z",
      "latest_scan_at": "2026-02-24T12:00:10Z",
      "latest_scan_profile": "nmap-tcp-default",
      "latest_open_ports": [22, 5432]
    }
  ]
}
```

## 7) Live Stream Endpoint

### `GET /stream/soc-live`
Server-Sent Events (SSE) stream for near real-time SOC snapshots.

Query params:
- `limit` (default `8`)
- `interval_sec` (default `3.0`)
- `once` (`true` for a single snapshot, useful for testing)
- `user_key` (RBAC key for browser EventSource clients when RBAC is enabled)

Stream event format:
```text
event: snapshot
data: {"timestamp":"...","incident_stats":{...},"error_stats":{...},"incidents":[...],"errors":[...],"scan_jobs":[...],"assets":[...]}
```

## 8) Error Intelligence Endpoints

### `GET /errors`
Filters:
- `limit`, `source`, `severity`, `error_type`, `search`

Response:
```json
{
  "items": [
    {
      "id": "uuid",
      "source": "openvas",
      "operation": "active_scan",
      "error_type": "RuntimeError",
      "message": "scan backend unavailable",
      "severity": "HIGH",
      "fingerprint": "sha256...",
      "occurrences": 3,
      "context": "target=127.0.0.1",
      "first_seen_at": "2026-02-24T12:00:00Z",
      "last_seen_at": "2026-02-24T12:10:00Z"
    }
  ]
}
```

### `GET /errors/stats/summary`
Manager/admin endpoint with total errors, total occurrences, last-24h counters, and groupings.

## 9) Outbound Delivery Endpoints

### `GET /outbound/events`
Manager/admin endpoint.

Filters:
- `limit`, `channel`, `status`, `event_type`

Response:
```json
{
  "items": [
    {
      "id": "uuid",
      "channel": "telegram",
      "event_type": "incident.created",
      "fingerprint": "sha256...",
      "status": "sent",
      "attempts": 2,
      "last_error": null,
      "first_attempt_at": "2026-02-24T12:00:00Z",
      "last_attempt_at": "2026-02-24T12:00:01Z",
      "sent_at": "2026-02-24T12:00:01Z",
      "created_at": "2026-02-24T12:00:00Z"
    }
  ]
}
```

### `GET /outbound/events/stats/summary`
Manager/admin endpoint with delivery KPIs.

## 10) Report Endpoints

### `GET /reports/operations`
Returns bilingual EN/UK operations summary with incident and error metrics.

### `GET /reports/operations/markdown`
Returns export-ready markdown (`text/plain`).
