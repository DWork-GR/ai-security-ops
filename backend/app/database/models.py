import uuid
from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    Text,
    Float,
    DateTime,
    ForeignKey
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database.db import Base


# =========================
# CVE — база знань
# =========================
class CVE(Base):
    __tablename__ = "cves"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(50), unique=True, nullable=False)
    cvss = Column(Float, nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text, nullable=False)
    mitigation = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


# =========================
# Incidents — IDS / Scanner
# =========================
class Incident(Base):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source = Column(String(50), nullable=False)       # snort / openvas
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    status = Column(String(20), default="new")        # new / analyzed / mitigated
    detected_at = Column(DateTime, default=datetime.utcnow)

    analysis = relationship(
        "AnalysisResult",
        back_populates="incident",
        uselist=False
    )


# =========================
# Analysis Results
# =========================
class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False
    )
    analysis_text = Column(Text, nullable=False)
    risk_level = Column(String(20), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    incident = relationship("Incident", back_populates="analysis")
