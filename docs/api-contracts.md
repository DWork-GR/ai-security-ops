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
  "incidents_updated": 0
}
```

## 3) Incident Endpoints

Headers for incident/report/knowledge/error endpoints when RBAC enabled:
- `X-User-Key: <analyst|manager|admin key>`

### `GET /incidents`
Filters:
- `limit`, `source`, `severity`, `status`, `search`, `min_risk`, `date_from`, `date_to`

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

## 4) Knowledge Base Endpoints

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

## 5) Error Intelligence Endpoints

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

## 6) Report Endpoints

### `GET /reports/operations`
Returns bilingual EN/UK operations summary with incident and error metrics.

### `GET /reports/operations/markdown`
Returns export-ready markdown (`text/plain`).
