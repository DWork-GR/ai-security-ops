import re
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.database.models import Incident
from app.database.repository import create_incident, create_incident_audit_log
from app.services.outbound_service import dispatch_incident_event

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SEVERITY_BASE_SCORE = {
    "LOW": 25.0,
    "MEDIUM": 50.0,
    "HIGH": 75.0,
    "CRITICAL": 95.0,
}

STATUS_MULTIPLIER = {
    "new": 1.0,
    "triaged": 0.9,
    "investigating": 0.95,
    "mitigated": 0.5,
    "closed": 0.2,
    "false_positive": 0.0,
}

SOURCE_BONUS = {
    "snort": 5.0,
    "openvas": 0.0,
    "nmap": 0.0,
}

ALLOWED_STATUSES = {
    "new",
    "triaged",
    "investigating",
    "mitigated",
    "closed",
    "false_positive",
}

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SPACE_REGEX = re.compile(r"\s+")


def normalize_severity(value: str) -> str:
    normalized = (value or "").upper().strip()
    if normalized in SEVERITY_RANK:
        return normalized
    return "MEDIUM"


def normalize_status(value: str) -> str:
    normalized = (value or "").lower().strip()
    if normalized in ALLOWED_STATUSES:
        return normalized
    raise ValueError(
        "Invalid incident status. Allowed: "
        + ", ".join(sorted(ALLOWED_STATUSES))
    )


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def infer_asset_from_text(message: str) -> str | None:
    match = IP_REGEX.search(message or "")
    if not match:
        return None
    return match.group(0)


def build_message_signature(message: str) -> str:
    normalized = (message or "").lower()
    normalized = IP_REGEX.sub("<ip>", normalized)
    normalized = SPACE_REGEX.sub(" ", normalized).strip()
    return normalized


def calculate_risk_score(
    *,
    severity: str,
    source: str,
    status: str,
) -> float:
    normalized_severity = normalize_severity(severity)
    normalized_status = (status or "").lower().strip()
    base = SEVERITY_BASE_SCORE[normalized_severity]
    bonus = SOURCE_BONUS.get((source or "").lower().strip(), 0.0)
    multiplier = STATUS_MULTIPLIER.get(normalized_status, 0.9)
    score = (base + bonus) * multiplier
    return round(max(0.0, min(100.0, score)), 1)


def correlate_incident(
    db: Session,
    *,
    source: str,
    message: str,
    severity: str,
    status: str = "new",
    asset: str | None = None,
    signature: str | None = None,
    actor_role: str = "system",
    window_hours: int = 24,
):
    normalized_source = (source or "").lower().strip()
    normalized_severity = normalize_severity(severity)
    normalized_status = normalize_status(status)
    normalized_asset = (asset or "").strip() or infer_asset_from_text(message)
    signature_source = (signature or "").strip() or message
    normalized_signature = build_message_signature(signature_source)
    threshold = _utc_now_naive() - timedelta(hours=window_hours)

    candidates = (
        db.query(Incident)
        .filter(
            Incident.source == normalized_source,
            Incident.detected_at >= threshold,
            Incident.status.notin_(["closed", "false_positive"]),
        )
        .order_by(Incident.detected_at.desc())
        .limit(250)
        .all()
    )

    existing = None
    for candidate in candidates:
        candidate_asset = infer_asset_from_text(candidate.message) or ""
        candidate_signature = build_message_signature(candidate.message)

        same_signature = candidate_signature == normalized_signature
        same_asset = bool(normalized_asset) and candidate_asset == normalized_asset

        if same_signature:
            existing = candidate
            break
        if same_asset:
            existing = candidate
            break

    if existing:
        old_severity = normalize_severity(existing.severity)
        old_rank = SEVERITY_RANK.get(old_severity, 2)
        new_rank = SEVERITY_RANK[normalized_severity]
        severity_escalated = False
        if new_rank > old_rank:
            existing.severity = normalized_severity
            severity_escalated = True
        existing.detected_at = _utc_now_naive()
        db.commit()
        db.refresh(existing)

        audit = create_incident_audit_log(
            db,
            incident_id=existing.id,
            action="correlated_update",
            old_status=existing.status,
            new_status=existing.status,
            actor_role=actor_role,
            details=f"signature={normalized_signature};asset={normalized_asset or 'n/a'}",
        )
        if severity_escalated:
            dispatch_incident_event(
                db,
                incident=existing,
                event_type="incident.severity_escalated",
                event_key=f"incident:{existing.id}:audit:{audit.id}",
            )
        return existing, False

    incident = create_incident(
        db,
        source=normalized_source,
        message=message,
        severity=normalized_severity,
        status=normalized_status,
    )
    audit = create_incident_audit_log(
        db,
        incident_id=incident.id,
        action="created",
        old_status=None,
        new_status=incident.status,
        actor_role=actor_role,
        details=f"signature={normalized_signature};asset={normalized_asset or 'n/a'}",
    )
    dispatch_incident_event(
        db,
        incident=incident,
        event_type="incident.created",
        event_key=f"incident:{incident.id}:audit:{audit.id}",
    )
    return incident, True
