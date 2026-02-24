from sqlalchemy.orm import Session

from app.database.models import CVE, Incident


def get_cve_by_id(db: Session, cve_id: str):
    return db.query(CVE).filter(CVE.cve_id == cve_id).first()


def get_all_cves(db: Session):
    return db.query(CVE).order_by(CVE.cvss.desc()).all()


def get_critical_cves(db: Session):
    return (
        db.query(CVE)
        .filter(CVE.severity == "CRITICAL")
        .order_by(CVE.cvss.desc())
        .all()
    )


def create_incident(
    db: Session,
    *,
    source: str,
    message: str,
    severity: str = "MEDIUM",
    status: str = "new",
):
    incident = Incident(
        source=source,
        message=message,
        severity=severity,
        status=status,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def list_incidents(db: Session, limit: int = 100):
    return (
        db.query(Incident)
        .order_by(Incident.detected_at.desc())
        .limit(limit)
        .all()
    )

