import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from app.database.db import Base


def _uuid_str() -> str:
    return str(uuid.uuid4())


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class CVE(Base):
    __tablename__ = "cves"

    id = Column(String(36), primary_key=True, default=_uuid_str)
    cve_id = Column(String(50), unique=True, nullable=False)
    cvss = Column(Float, nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text, nullable=False)
    mitigation = Column(Text, nullable=False)
    created_at = Column(DateTime, default=_utc_now_naive, nullable=False)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=_uuid_str)
    source = Column(String(50), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    status = Column(String(20), default="new", nullable=False)
    detected_at = Column(DateTime, default=_utc_now_naive, nullable=False)

    analysis = relationship("AnalysisResult", back_populates="incident", uselist=False)


class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(String(36), primary_key=True, default=_uuid_str)
    incident_id = Column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    analysis_text = Column(Text, nullable=False)
    risk_level = Column(String(20), nullable=False)
    created_at = Column(DateTime, default=_utc_now_naive, nullable=False)

    incident = relationship("Incident", back_populates="analysis")
