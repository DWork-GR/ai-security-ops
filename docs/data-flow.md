## Data Flow

### 1. High-Level Sequence

1. External signal appears:
- Snort IDS alert
- OpenVAS scan request/result

2. API receives payload:
- Validates schema and source
- Assigns trace id

3. Normalization:
- Maps source-specific format to unified event structure

4. Correlation:
- Matches event by asset/time/signature
- Attaches to existing incident or creates new incident

5. Prioritization:
- Severity score from source priority + CVSS + heuristics

6. Analysis:
- Rule-based recommendation (deterministic baseline)
- Optional LLM enrichment

7. Response:
- UI and/or API consumer gets structured result
- Incident state persisted for reporting

### 2. Event Envelope (Unified)

```json
{
  "source": "snort|openvas",
  "event_type": "ids_alert|vuln_scan_result",
  "title": "short event title",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "priority": 1,
  "asset": "10.0.0.5",
  "detected_at": "2026-02-24T12:00:00Z",
  "raw": "original payload fragment"
}
```

### 3. Correlation Rules (MVP)

Rule 1:
- Same asset + same vulnerability/signature within 24h -> same incident.

Rule 2:
- Priority 1 Snort alert + matching critical CVE on same asset -> escalate risk.

Rule 3:
- Repeated medium events (>=5 in 1h) -> create high-priority incident.

### 4. Failure Paths

- Invalid payload -> `400` with validation details.
- Dependency outage (DB/LLM) -> `503` with fallback message.
- Partial integration result -> persist what is available, mark status `needs_review`.
