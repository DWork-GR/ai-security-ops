## API Contracts

Base URL: `/`

## 1) Chat Endpoint (UI helper, not core integration endpoint)

### `POST /chat`
Request:
```json
{
  "message": "show critical cves"
}
```

Response (`type=text`):
```json
{
  "type": "text",
  "message": "Human-readable answer"
}
```

Response (`type=cves`):
```json
{
  "type": "cves",
  "cves": [
    {
      "cve_id": "CVE-2021-44228",
      "cvss": 10.0,
      "severity": "CRITICAL",
      "description": "Description",
      "mitigation": "Action"
    }
  ]
}
```

## 2) Snort Integration

### `POST /integrations/snort/alerts`
Headers:
- `X-API-Key: <shared_key>` (required when `INTEGRATION_API_KEY` is configured)

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

## 3) OpenVAS Integration

### `POST /integrations/openvas/scan`
Headers:
- `X-API-Key: <shared_key>` (required when `INTEGRATION_API_KEY` is configured)

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

## 4) Incident Query

### `GET /incidents`
Response:
```json
{
  "items": [
    {
      "id": "uuid",
      "source": "snort",
      "severity": "HIGH",
      "status": "new",
      "detected_at": "2026-02-24T12:00:00Z"
    }
  ]
}
```

## 5) Error Contract

All validation errors:
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Details"
  }
}
```
