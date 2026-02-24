## AI Security Ops - Integration-First Architecture

### 1. Goal
Build an integration-centric SOC assistant where chat is only one client.
Core value: normalize and correlate security data from external tools
(Snort IDS and OpenVAS scanner), then produce actionable incidents.

### 2. Logical Components

1. API Layer (FastAPI)
- Exposes ingestion and query endpoints.
- Handles auth, validation, and response contracts.

2. Integration Adapters
- `integrations/snort/*`: parse incoming or file-based Snort alerts.
- `integrations/openvas/*`: create scan tasks and process scan results.

3. Domain Services
- Incident creation and deduplication.
- Threat analysis orchestration (rule-based and LLM-assisted).

4. Persistence Layer (PostgreSQL via SQLAlchemy)
- Stores CVEs, incidents, and analysis results.
- Designed for deterministic queries and report generation.

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

### 6. Security Controls Baseline

- Secrets only from environment, never hardcoded in repository.
- Strict CORS allowlist (development vs production profiles).
- Output sanitization on frontend and structured responses on backend.
- Input validation on all integration endpoints.
- Auditable incident lifecycle states: `new`, `triaged`, `mitigated`, `closed`.

### 7. Defense Narrative
On defense day, demonstrate:
1. Snort alert ingestion creates incident.
2. OpenVAS scan result enriches same incident or creates new one.
3. System returns prioritized response recommendation.
4. Analyst updates incident status and evidence is persisted.
