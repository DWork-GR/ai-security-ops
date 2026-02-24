## AI Security Ops - Integration-First Architecture

### 1. Goal
Build an integration-centric SOC assistant where chat is only one client.
Core value: normalize and correlate security data from external tools
(Snort IDS and OpenVAS scanner), then produce actionable incidents.

### 2. Logical Components

1. API Layer (FastAPI)
- Exposes ingestion and query endpoints.
- Handles auth, validation, and response contracts.
- Enforces optional RBAC with analyst/manager/admin roles.
- Exposes scan-job queue APIs for asynchronous execution tracking.

2. Integration Adapters
- `integrations/snort/*`: parse incoming or file-based Snort alerts.
- `integrations/openvas/*`: create scan tasks and execute active TCP scan profile.
- `integrations/nmap/*`: run network discovery scans (native nmap with socket fallback).
- Outbound adapters: Telegram alerts, GitHub Issues ticketing, optional webhook.

3. Domain Services
- Incident creation and deduplication.
- Threat analysis orchestration (rule-based and LLM-assisted).
- Correlation v2 using signature + asset inference + severity escalation.
- Scan service maps open services to KB CVEs and creates incidents.
- Error service fingerprints backend failures for operational troubleshooting.
- Outbound service delivers incident events with retry and idempotency by channel/event key.
- Scan job service executes scan profiles (`quick`, `discovery`, `vulnerability`, `full`).
- Background worker polls queued jobs and runs scans outside request lifecycle.

4. Persistence Layer (PostgreSQL via SQLAlchemy)
- Stores CVEs, incidents, analysis results, and error events.
- Designed for deterministic queries and report generation.
- Stores incident audit trail for lifecycle accountability.

5. Presentation Layer
- Web UI can call chat-style endpoint.
- Same backend also supports machine-to-machine integration endpoints.

### 3. Architectural Principle
Use explicit SOC pipeline stages:
`Ingest -> Normalize -> Correlate -> Prioritize -> Recommend -> Track`.
This is the diploma focus, not UI polish.

### 4. Data Model (Current + Target)

Current entities:
- `CVE`
- `Incident`
- `AnalysisResult`
- `IncidentAuditLog`
- `ErrorEvent`
- `ScanJob`
- `ScanRun`
- `ScanFinding`
- `OutboundEvent`

Target additions (next iterations):
- `IntegrationEvent` (raw event envelope)
- `Asset` (host/service ownership)
- `CorrelationLink` (event-to-incident mapping)

### 5. Integration Strategy

Snort:
- Accept alerts in JSON payloads or parse `alert.fast`.
- Normalize into common event schema:
  - `source`, `event_type`, `severity`, `title`, `raw`, `detected_at`.

OpenVAS:
- Start scan by target IP/CIDR.
- Persist task metadata and result summary.
- Convert vulnerabilities to incident candidates by severity threshold.

Nmap:
- Run active discovery by target IP and optional custom ports.
- Return same structured response as OpenVAS active scan.
- Persist scan baselines for new/closed open port diff.

### 6. Security Controls Baseline

- Secrets only from environment, never hardcoded in repository.
- Strict CORS allowlist (development vs production profiles).
- Output sanitization on frontend and structured responses on backend.
- Input validation on all integration endpoints.
- Auditable incident lifecycle states: `new`, `triaged`, `mitigated`, `closed`.
- Manager-grade reporting endpoint for exportable operations summaries.

### 7. Defense Narrative
On defense day, demonstrate:
1. Snort alert ingestion creates incident.
2. OpenVAS scan result enriches same incident or creates new one.
3. System returns prioritized response recommendation.
4. Analyst updates incident status and evidence is persisted.
