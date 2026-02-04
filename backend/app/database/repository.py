from sqlalchemy.orm import Session
from app.database.models import CVE


def get_cve_by_id(db: Session, cve_id: str):
    return db.query(CVE).filter(CVE.id == cve_id).first()
