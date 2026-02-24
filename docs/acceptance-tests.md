## Acceptance Tests (Diploma Demo)

### AT-01: Critical CVE listing
Preconditions:
- DB seeded with CVE records including CRITICAL.

Steps:
1. Send `POST /chat` with `message="critical vulnerabilities"`.

Expected:
- `200 OK`.
- Response `type="cves"`.
- At least one item has `severity="CRITICAL"`.

### AT-02: CVE lookup
Preconditions:
- DB contains `CVE-2021-44228`.

Steps:
1. Send `POST /chat` with `message="CVE-2021-44228"`.

Expected:
- `200 OK`.
- Response `type="text"`.
- Message includes CVSS and mitigation.

### AT-03: Start OpenVAS scan by target
Steps:
1. Send `POST /chat` with `message="scan 10.0.0.5"`.

Expected:
- `200 OK`.
- Response confirms scan task id and target.

### AT-04: Analyze Snort critical alerts
Preconditions:
- `alert.fast` contains at least one priority 1 alert.

Steps:
1. Send `POST /chat` with `message="analyze threats"`.

Expected:
- `200 OK`.
- Response includes incident-oriented analysis and actions.

### AT-05: XSS safety in frontend output
Steps:
1. Send payload that includes `<script>alert(1)</script>` in text field.
2. Render message in UI.

Expected:
- Script is not executed.
- Unsafe markup is escaped or stripped.

### AT-06: Secret hygiene
Steps:
1. Verify `.env` is ignored by git.
2. Verify `.env.example` exists with placeholders only.

Expected:
- Secrets are not tracked in repository.

### AT-07: Snort deduplication
Steps:
1. Send `POST /integrations/snort/alerts` with one alert.
2. Send the same request again within 24 hours.

Expected:
- First request: `incidents_created=1`, `incidents_updated=0`.
- Second request: `incidents_created=0`, `incidents_updated=1`.

### AT-08: Integration API key enforcement
Preconditions:
- `INTEGRATION_API_KEY` is configured.

Steps:
1. Call `POST /integrations/openvas/scan` without `X-API-Key`.
2. Call same endpoint with wrong key.
3. Call same endpoint with correct key.

Expected:
- Calls 1 and 2 return `401`.
- Call 3 returns `200`.

### AT-09: Incident workflow status update
Steps:
1. Create incident using integration endpoint.
2. Update status via `PATCH /incidents/{id}/status` to `triaged`.
3. Filter incidents by `status=triaged`.

Expected:
- Status update returns `200`.
- Filtered list contains updated incident.

### AT-10: SOC KPI and report endpoint
Steps:
1. Create incidents from at least two sources (`snort`, `openvas`).
2. Call `GET /incidents/stats/summary`.
3. Call `GET /reports/operations`.

Expected:
- Stats endpoint returns counts by source/severity/status.
- Report endpoint returns non-empty EN and UK summaries.

### AT-11: RBAC protection for manager-only endpoints
Preconditions:
- `RBAC_ENABLED=true` and valid `RBAC_KEYS`.

Steps:
1. Call `GET /reports/operations` with analyst key.
2. Call same endpoint with manager key.

Expected:
- Analyst request returns `403`.
- Manager request returns `200`.

### AT-12: Audit trail visibility
Steps:
1. Create incident.
2. Change status via `PATCH /incidents/{id}/status`.
3. Open `GET /incidents/{id}/audit`.

Expected:
- Audit list contains `status_changed` record with role and timestamps.

### AT-13: Active scan with structured findings
Steps:
1. Call `POST /integrations/openvas/scan/active` for `127.0.0.1` with custom ports.
2. Check response fields.

Expected:
- `200 OK`.
- Response contains `open_ports`, `findings`, `incidents_created`, and `incidents_updated`.

### AT-14: Knowledge base filtered search
Steps:
1. Call `GET /knowledge/cves/search?q=apache&min_cvss=9`.

Expected:
- `200 OK`.
- Non-empty list of CVEs with `cvss >= 9`.

### AT-15: Error intelligence flow
Steps:
1. Force integration failure (for example, runtime error in active scan).
2. Call `GET /errors`.
3. Call `GET /errors/stats/summary`.

Expected:
- Error entry is persisted with source, operation, type, and occurrence count.
- Stats endpoint reports at least one error event.
