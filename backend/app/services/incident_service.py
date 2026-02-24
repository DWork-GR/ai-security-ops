from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.database.models import Incident
from app.database.repository import create_incident

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def normalize_severity(value: str) -> str:
    normalized = (value or "").upper().strip()
    if normalized in SEVERITY_RANK:
        return normalized
    return "MEDIUM"


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def correlate_incident(
    db: Session,
    *,
    source: str,
    message: str,
    severity: str,
    status: str = "new",
    window_hours: int = 24,
):
    normalized_severity = normalize_severity(severity)
    threshold = _utc_now_naive() - timedelta(hours=window_hours)

    existing = (
        db.query(Incident)
        .filter(
            Incident.source == source,
            Incident.message == message,
            Incident.detected_at >= threshold,
            Incident.status != "closed",
        )
        .order_by(Incident.detected_at.desc())
        .first()
    )

    if existing:
        current_rank = SEVERITY_RANK.get(normalize_severity(existing.severity), 2)
        new_rank = SEVERITY_RANK[normalized_severity]
        if new_rank > current_rank:
            existing.severity = normalized_severity

        existing.detected_at = _utc_now_naive()
        db.commit()
        db.refresh(existing)
        return existing, False

    incident = create_incident(
        db,
        source=source,
        message=message,
        severity=normalized_severity,
        status=status,
    )
    return incident, True
