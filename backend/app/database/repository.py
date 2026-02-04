from sqlalchemy.orm import Session
from app.database.models import CVE


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
