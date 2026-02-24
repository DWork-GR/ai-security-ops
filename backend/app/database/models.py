import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
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
    audit_logs = relationship(
        "IncidentAuditLog",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentAuditLog.created_at.desc()",
    )


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


class IncidentAuditLog(Base):
    __tablename__ = "incident_audit_logs"

    id = Column(String(36), primary_key=True, default=_uuid_str)
    incident_id = Column(
        String(36),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
    )
    action = Column(String(50), nullable=False)
    old_status = Column(String(20), nullable=True)
    new_status = Column(String(20), nullable=True)
    actor_role = Column(String(20), nullable=False)
    actor_id = Column(String(120), nullable=True)
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_utc_now_naive, nullable=False)

    incident = relationship("Incident", back_populates="audit_logs")


class ErrorEvent(Base):
    __tablename__ = "error_events"

    id = Column(String(36), primary_key=True, default=_uuid_str)
    source = Column(String(50), nullable=False)
    operation = Column(String(120), nullable=False)
    error_type = Column(String(120), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="MEDIUM")
    fingerprint = Column(String(64), nullable=False, unique=True)
    occurrences = Column(Integer, nullable=False, default=1)
    context = Column(Text, nullable=True)
    first_seen_at = Column(DateTime, default=_utc_now_naive, nullable=False)
    last_seen_at = Column(DateTime, default=_utc_now_naive, nullable=False)


class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=_uuid_str)
    ip = Column(String(64), nullable=False, unique=True)
    hostname = Column(String(255), nullable=True)
    owner = Column(String(120), nullable=True)
    business_unit = Column(String(120), nullable=True)
    criticality = Column(String(20), nullable=False, default="MEDIUM")
    environment = Column(String(30), nullable=False, default="unknown")
    tags = Column(Text, nullable=True)
    first_seen_at = Column(DateTime, default=_utc_now_naive, nullable=False)
    last_seen_at = Column(DateTime, default=_utc_now_naive, nullable=False)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(String(36), primary_key=True, default=_uuid_str)
    task_id = Column(String(36), nullable=False, unique=True)
    target_ip = Column(String(64), nullable=False)
    scan_profile = Column(String(60), nullable=False)
    status = Column(String(20), nullable=False, default="completed")
    scanned_ports = Column(Integer, nullable=False, default=0)
    open_ports_count = Column(Integer, nullable=False, default=0)
    duration_ms = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime, default=_utc_now_naive, nullable=False)
    finished_at = Column(DateTime, default=_utc_now_naive, nullable=False)

    findings = relationship(
        "ScanFinding",
        back_populates="scan_run",
        cascade="all, delete-orphan",
    )


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id = Column(String(36), primary_key=True, default=_uuid_str)
    scan_run_id = Column(
        String(36),
        ForeignKey("scan_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    port = Column(Integer, nullable=False)
    protocol = Column(String(16), nullable=False)
    service = Column(String(60), nullable=False)
    severity = Column(String(20), nullable=False)
    risk_score = Column(Float, nullable=False, default=0.0)
    cvss_max = Column(Float, nullable=False, default=0.0)
    cve_refs = Column(Text, nullable=True)
    summary_en = Column(Text, nullable=False)
    summary_uk = Column(Text, nullable=False)
    fingerprint = Column(String(255), nullable=False)

    scan_run = relationship("ScanRun", back_populates="findings")
