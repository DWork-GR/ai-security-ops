from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.database.models import (
    Asset,
    CVE,
    ErrorEvent,
    Incident,
    IncidentAuditLog,
    OutboundEvent,
    ScanJob,
    ScanFinding,
    ScanRun,
)

ALLOWED_STATUSES = {
    "new",
    "triaged",
    "investigating",
    "mitigated",
    "closed",
    "false_positive",
}

ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_ASSET_CRITICALITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_OUTBOUND_STATUSES = {"pending", "sent", "failed", "skipped"}
ALLOWED_SCAN_JOB_STATUSES = {"queued", "running", "completed", "failed", "cancelled"}
ALLOWED_SCAN_JOB_TYPES = {"quick", "discovery", "vulnerability", "full"}


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _normalize_status(value: str) -> str:
    normalized = (value or "").lower().strip()
    if normalized in ALLOWED_STATUSES:
        return normalized
    raise ValueError(
        "Invalid incident status. Allowed: "
        + ", ".join(sorted(ALLOWED_STATUSES))
    )


def _normalize_severity(value: str) -> str:
    normalized = (value or "").upper().strip()
    if normalized in ALLOWED_SEVERITIES:
        return normalized
    raise ValueError(
        "Invalid severity. Allowed: "
        + ", ".join(sorted(ALLOWED_SEVERITIES))
    )


def _normalize_asset_criticality(value: str) -> str:
    normalized = (value or "").upper().strip()
    if normalized in ALLOWED_ASSET_CRITICALITIES:
        return normalized
    raise ValueError(
        "Invalid asset criticality. Allowed: "
        + ", ".join(sorted(ALLOWED_ASSET_CRITICALITIES))
    )


def _normalize_outbound_status(value: str) -> str:
    normalized = (value or "").lower().strip()
    if normalized in ALLOWED_OUTBOUND_STATUSES:
        return normalized
    raise ValueError(
        "Invalid outbound status. Allowed: "
        + ", ".join(sorted(ALLOWED_OUTBOUND_STATUSES))
    )


def _normalize_scan_job_status(value: str) -> str:
    normalized = (value or "").lower().strip()
    if normalized in ALLOWED_SCAN_JOB_STATUSES:
        return normalized
    raise ValueError(
        "Invalid scan job status. Allowed: "
        + ", ".join(sorted(ALLOWED_SCAN_JOB_STATUSES))
    )


def _normalize_scan_job_type(value: str) -> str:
    normalized = (value or "").lower().strip()
    if normalized in ALLOWED_SCAN_JOB_TYPES:
        return normalized
    raise ValueError(
        "Invalid scan type. Allowed: "
        + ", ".join(sorted(ALLOWED_SCAN_JOB_TYPES))
    )


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


def search_cves(
    db: Session,
    *,
    query: str | None = None,
    severity: str | None = None,
    min_cvss: float | None = None,
    limit: int = 100,
):
    q = db.query(CVE)
    if query:
        pattern = f"%{query.strip()}%"
        q = q.filter(
            or_(
                CVE.cve_id.ilike(pattern),
                CVE.description.ilike(pattern),
                CVE.mitigation.ilike(pattern),
            )
        )
    if severity:
        q = q.filter(CVE.severity == _normalize_severity(severity))
    if min_cvss is not None:
        q = q.filter(CVE.cvss >= float(min_cvss))

    return q.order_by(CVE.cvss.desc(), CVE.cve_id.asc()).limit(limit).all()


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


def list_incidents(
    db: Session,
    *,
    limit: int = 100,
    source: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    search: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
):
    query = db.query(Incident)

    if source:
        query = query.filter(Incident.source == source.lower().strip())
    if severity:
        query = query.filter(Incident.severity == severity.upper().strip())
    if status:
        normalized_status = _normalize_status(status)
        query = query.filter(Incident.status == normalized_status)
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(or_(Incident.message.ilike(pattern), Incident.source.ilike(pattern)))
    if date_from:
        query = query.filter(Incident.detected_at >= date_from)
    if date_to:
        query = query.filter(Incident.detected_at <= date_to)

    return (
        query.order_by(Incident.detected_at.desc())
        .limit(limit)
        .all()
    )


def get_incident_by_id(db: Session, incident_id: str):
    return db.query(Incident).filter(Incident.id == incident_id).first()


def update_incident_status(db: Session, incident: Incident, status: str):
    incident.status = _normalize_status(status)
    db.commit()
    db.refresh(incident)
    return incident


def create_incident_audit_log(
    db: Session,
    *,
    incident_id: str,
    action: str,
    old_status: str | None,
    new_status: str | None,
    actor_role: str,
    actor_id: str | None = None,
    details: str | None = None,
):
    record = IncidentAuditLog(
        incident_id=incident_id,
        action=action,
        old_status=old_status,
        new_status=new_status,
        actor_role=actor_role,
        actor_id=actor_id,
        details=details,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def list_incident_audit_logs(db: Session, incident_id: str, limit: int = 100):
    return (
        db.query(IncidentAuditLog)
        .filter(IncidentAuditLog.incident_id == incident_id)
        .order_by(IncidentAuditLog.created_at.desc())
        .limit(limit)
        .all()
    )


def get_incident_summary_stats(db: Session):
    status_rows = db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all()
    severity_rows = (
        db.query(Incident.severity, func.count(Incident.id))
        .group_by(Incident.severity)
        .all()
    )
    source_rows = db.query(Incident.source, func.count(Incident.id)).group_by(Incident.source).all()

    total_incidents = db.query(func.count(Incident.id)).scalar() or 0
    window_start = _utc_now_naive() - timedelta(hours=24)
    incidents_last_24h = (
        db.query(func.count(Incident.id))
        .filter(Incident.detected_at >= window_start)
        .scalar()
        or 0
    )

    open_statuses = ["new", "triaged", "investigating"]
    open_incidents = (
        db.query(func.count(Incident.id))
        .filter(Incident.status.in_(open_statuses))
        .scalar()
        or 0
    )
    critical_open_incidents = (
        db.query(func.count(Incident.id))
        .filter(
            Incident.status.in_(open_statuses),
            Incident.severity == "CRITICAL",
        )
        .scalar()
        or 0
    )

    return {
        "total_incidents": int(total_incidents),
        "open_incidents": int(open_incidents),
        "critical_open_incidents": int(critical_open_incidents),
        "incidents_last_24h": int(incidents_last_24h),
        "by_status": {row[0]: int(row[1]) for row in status_rows},
        "by_severity": {row[0]: int(row[1]) for row in severity_rows},
        "by_source": {row[0]: int(row[1]) for row in source_rows},
    }


def create_or_increment_error_event(
    db: Session,
    *,
    source: str,
    operation: str,
    error_type: str,
    message: str,
    severity: str,
    fingerprint: str,
    context: str | None = None,
):
    normalized_source = (source or "unknown").lower().strip() or "unknown"
    normalized_operation = (operation or "unknown").strip() or "unknown"
    normalized_type = (error_type or "Exception").strip() or "Exception"
    normalized_message = (message or "").strip() or "Unknown error"
    normalized_severity = _normalize_severity(severity)

    existing = db.query(ErrorEvent).filter(ErrorEvent.fingerprint == fingerprint).first()
    now = _utc_now_naive()
    if existing:
        existing.occurrences += 1
        existing.last_seen_at = now
        if context:
            existing.context = context
        db.commit()
        db.refresh(existing)
        return existing

    item = ErrorEvent(
        source=normalized_source,
        operation=normalized_operation,
        error_type=normalized_type,
        message=normalized_message,
        severity=normalized_severity,
        fingerprint=fingerprint,
        context=context,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def list_error_events(
    db: Session,
    *,
    limit: int = 100,
    source: str | None = None,
    severity: str | None = None,
    error_type: str | None = None,
    search: str | None = None,
):
    query = db.query(ErrorEvent)
    if source:
        query = query.filter(ErrorEvent.source == source.lower().strip())
    if severity:
        query = query.filter(ErrorEvent.severity == _normalize_severity(severity))
    if error_type:
        query = query.filter(ErrorEvent.error_type == error_type.strip())
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                ErrorEvent.message.ilike(pattern),
                ErrorEvent.operation.ilike(pattern),
                ErrorEvent.error_type.ilike(pattern),
            )
        )

    return query.order_by(ErrorEvent.last_seen_at.desc()).limit(limit).all()


def get_error_summary_stats(db: Session):
    now = _utc_now_naive()
    window_start = now - timedelta(hours=24)

    total_errors = db.query(func.count(ErrorEvent.id)).scalar() or 0
    last_24h_errors = (
        db.query(func.count(ErrorEvent.id))
        .filter(ErrorEvent.last_seen_at >= window_start)
        .scalar()
        or 0
    )

    severity_rows = (
        db.query(ErrorEvent.severity, func.count(ErrorEvent.id))
        .group_by(ErrorEvent.severity)
        .all()
    )
    source_rows = (
        db.query(ErrorEvent.source, func.count(ErrorEvent.id))
        .group_by(ErrorEvent.source)
        .all()
    )
    type_rows = (
        db.query(ErrorEvent.error_type, func.count(ErrorEvent.id))
        .group_by(ErrorEvent.error_type)
        .all()
    )
    occurrences_total = db.query(func.sum(ErrorEvent.occurrences)).scalar() or 0

    return {
        "total_errors": int(total_errors),
        "errors_last_24h": int(last_24h_errors),
        "total_occurrences": int(occurrences_total),
        "by_severity": {row[0]: int(row[1]) for row in severity_rows},
        "by_source": {row[0]: int(row[1]) for row in source_rows},
        "by_type": {row[0]: int(row[1]) for row in type_rows},
    }


def get_platform_overview_stats(db: Session):
    last_scan_at = db.query(func.max(ScanRun.finished_at)).scalar()
    return {
        "total_cves": int(db.query(func.count(CVE.id)).scalar() or 0),
        "total_assets": int(db.query(func.count(Asset.id)).scalar() or 0),
        "total_scan_runs": int(db.query(func.count(ScanRun.id)).scalar() or 0),
        "total_scan_findings": int(db.query(func.count(ScanFinding.id)).scalar() or 0),
        "total_incidents": int(db.query(func.count(Incident.id)).scalar() or 0),
        "total_errors": int(db.query(func.count(ErrorEvent.id)).scalar() or 0),
        "last_scan_at": last_scan_at.isoformat() if last_scan_at else None,
    }


def get_asset_by_ip(db: Session, ip: str):
    return db.query(Asset).filter(Asset.ip == ip.strip()).first()


def upsert_asset(
    db: Session,
    *,
    ip: str,
    hostname: str | None = None,
    owner: str | None = None,
    business_unit: str | None = None,
    criticality: str | None = None,
    environment: str | None = None,
    tags: str | None = None,
):
    normalized_ip = (ip or "").strip()
    if not normalized_ip:
        raise ValueError("Asset IP is required")

    asset = get_asset_by_ip(db, normalized_ip)
    now = _utc_now_naive()

    normalized_criticality = None
    if criticality:
        normalized_criticality = _normalize_asset_criticality(criticality)

    if asset:
        asset.last_seen_at = now
        if hostname is not None:
            asset.hostname = hostname
        if owner is not None:
            asset.owner = owner
        if business_unit is not None:
            asset.business_unit = business_unit
        if normalized_criticality is not None:
            asset.criticality = normalized_criticality
        if environment is not None:
            asset.environment = environment.strip() or "unknown"
        if tags is not None:
            asset.tags = tags
        db.commit()
        db.refresh(asset)
        return asset

    asset = Asset(
        ip=normalized_ip,
        hostname=hostname,
        owner=owner,
        business_unit=business_unit,
        criticality=normalized_criticality or "MEDIUM",
        environment=(environment.strip() if environment else "unknown"),
        tags=tags,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def list_assets(
    db: Session,
    *,
    limit: int = 200,
    criticality: str | None = None,
    environment: str | None = None,
    search: str | None = None,
):
    query = db.query(Asset)
    if criticality:
        query = query.filter(Asset.criticality == _normalize_asset_criticality(criticality))
    if environment:
        query = query.filter(Asset.environment == environment.strip())
    if search:
        pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Asset.ip.ilike(pattern),
                Asset.hostname.ilike(pattern),
                Asset.owner.ilike(pattern),
                Asset.business_unit.ilike(pattern),
                Asset.tags.ilike(pattern),
            )
        )

    return query.order_by(Asset.last_seen_at.desc()).limit(limit).all()


def create_scan_run(
    db: Session,
    *,
    task_id: str,
    target_ip: str,
    scan_profile: str,
    status: str,
    scanned_ports: int,
    open_ports_count: int,
    duration_ms: int,
    started_at: datetime,
    finished_at: datetime,
):
    item = ScanRun(
        task_id=task_id,
        target_ip=target_ip,
        scan_profile=scan_profile,
        status=status,
        scanned_ports=scanned_ports,
        open_ports_count=open_ports_count,
        duration_ms=duration_ms,
        started_at=started_at,
        finished_at=finished_at,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def add_scan_finding(
    db: Session,
    *,
    scan_run_id: str,
    port: int,
    protocol: str,
    service: str,
    severity: str,
    risk_score: float,
    cvss_max: float,
    cve_refs: list[str],
    summary_en: str,
    summary_uk: str,
    fingerprint: str,
):
    item = ScanFinding(
        scan_run_id=scan_run_id,
        port=int(port),
        protocol=protocol,
        service=service,
        severity=_normalize_severity(severity),
        risk_score=float(risk_score),
        cvss_max=float(cvss_max),
        cve_refs=",".join(cve_refs) if cve_refs else "",
        summary_en=summary_en,
        summary_uk=summary_uk,
        fingerprint=fingerprint,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def list_scan_findings_by_run(db: Session, scan_run_id: str):
    return (
        db.query(ScanFinding)
        .filter(ScanFinding.scan_run_id == scan_run_id)
        .order_by(ScanFinding.risk_score.desc(), ScanFinding.port.asc())
        .all()
    )


def get_latest_scan_run_for_target(db: Session, target_ip: str):
    return (
        db.query(ScanRun)
        .filter(ScanRun.target_ip == target_ip.strip())
        .order_by(ScanRun.finished_at.desc())
        .first()
    )


def list_scan_runs(
    db: Session,
    *,
    target_ip: str | None = None,
    limit: int = 100,
):
    query = db.query(ScanRun)
    if target_ip:
        query = query.filter(ScanRun.target_ip == target_ip.strip())
    return query.order_by(ScanRun.finished_at.desc()).limit(limit).all()


def get_scan_run_by_task_id(db: Session, task_id: str):
    return db.query(ScanRun).filter(ScanRun.task_id == task_id.strip()).first()


def list_open_ports_for_scan_run(db: Session, scan_run_id: str):
    rows = (
        db.query(ScanFinding.port)
        .filter(ScanFinding.scan_run_id == scan_run_id)
        .all()
    )
    return sorted({int(row[0]) for row in rows})


def create_scan_job(
    db: Session,
    *,
    target_ip: str,
    scan_type: str,
    requested_by: str | None = None,
):
    normalized_target = (target_ip or "").strip()
    if not normalized_target:
        raise ValueError("target_ip is required")

    item = ScanJob(
        target_ip=normalized_target,
        scan_type=_normalize_scan_job_type(scan_type),
        status="queued",
        requested_by=(requested_by or "").strip() or None,
        attempts=0,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def list_scan_jobs(
    db: Session,
    *,
    limit: int = 100,
    status: str | None = None,
    scan_type: str | None = None,
    target_ip: str | None = None,
):
    query = db.query(ScanJob)
    if status:
        query = query.filter(ScanJob.status == _normalize_scan_job_status(status))
    if scan_type:
        query = query.filter(ScanJob.scan_type == _normalize_scan_job_type(scan_type))
    if target_ip:
        query = query.filter(ScanJob.target_ip == target_ip.strip())

    return query.order_by(ScanJob.created_at.desc()).limit(limit).all()


def get_scan_job_by_id(db: Session, job_id: str):
    return db.query(ScanJob).filter(ScanJob.id == job_id).first()


def get_next_queued_scan_job(db: Session):
    return (
        db.query(ScanJob)
        .filter(ScanJob.status == "queued")
        .order_by(ScanJob.created_at.asc())
        .first()
    )


def mark_scan_job_running(db: Session, item: ScanJob):
    now = _utc_now_naive()
    item.status = "running"
    item.attempts = int(item.attempts or 0) + 1
    if not item.started_at:
        item.started_at = now
    item.last_error = None
    db.commit()
    db.refresh(item)
    return item


def mark_scan_job_completed(
    db: Session,
    item: ScanJob,
    *,
    result_summary: str,
):
    item.status = "completed"
    item.result_summary = result_summary
    item.last_error = None
    item.finished_at = _utc_now_naive()
    db.commit()
    db.refresh(item)
    return item


def mark_scan_job_failed(
    db: Session,
    item: ScanJob,
    *,
    error_message: str,
):
    item.status = "failed"
    item.last_error = (error_message or "Unknown scan job error").strip()[:4000]
    item.finished_at = _utc_now_naive()
    db.commit()
    db.refresh(item)
    return item


def cancel_scan_job(db: Session, item: ScanJob):
    if item.status in {"completed", "failed", "cancelled"}:
        return item
    item.status = "cancelled"
    item.finished_at = _utc_now_naive()
    db.commit()
    db.refresh(item)
    return item


def upsert_cves(
    db: Session,
    records: list[dict],
):
    created = 0
    updated = 0
    for record in records:
        cve_id = (record.get("cve_id") or "").strip().upper()
        if not cve_id:
            continue
        existing = db.query(CVE).filter(CVE.cve_id == cve_id).first()
        if existing:
            existing.cvss = float(record.get("cvss", existing.cvss))
            existing.severity = _normalize_severity(record.get("severity", existing.severity))
            existing.description = record.get("description", existing.description)
            existing.mitigation = record.get("mitigation", existing.mitigation)
            updated += 1
            continue

        db.add(
            CVE(
                cve_id=cve_id,
                cvss=float(record.get("cvss", 0.0)),
                severity=_normalize_severity(record.get("severity", "MEDIUM")),
                description=(record.get("description") or "No description provided").strip(),
                mitigation=(record.get("mitigation") or "Review vendor advisories and apply patches.").strip(),
            )
        )
        created += 1

    db.commit()
    return created, updated


def get_outbound_event_by_fingerprint(db: Session, fingerprint: str):
    return (
        db.query(OutboundEvent)
        .filter(OutboundEvent.fingerprint == fingerprint.strip())
        .first()
    )


def create_outbound_event(
    db: Session,
    *,
    channel: str,
    event_type: str,
    fingerprint: str,
    payload: str,
):
    item = OutboundEvent(
        channel=(channel or "").strip().lower(),
        event_type=(event_type or "").strip().lower(),
        fingerprint=fingerprint.strip(),
        payload=payload,
        status="pending",
        attempts=0,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def mark_outbound_attempt_failed(
    db: Session,
    item: OutboundEvent,
    *,
    error_message: str,
):
    now = _utc_now_naive()
    item.status = "failed"
    item.attempts = int(item.attempts or 0) + 1
    if not item.first_attempt_at:
        item.first_attempt_at = now
    item.last_attempt_at = now
    item.last_error = (error_message or "Unknown delivery error").strip()[:2000]
    db.commit()
    db.refresh(item)
    return item


def mark_outbound_attempt_sent(db: Session, item: OutboundEvent):
    now = _utc_now_naive()
    item.status = "sent"
    item.attempts = int(item.attempts or 0) + 1
    if not item.first_attempt_at:
        item.first_attempt_at = now
    item.last_attempt_at = now
    item.sent_at = now
    item.last_error = None
    db.commit()
    db.refresh(item)
    return item


def mark_outbound_skipped(
    db: Session,
    item: OutboundEvent,
    *,
    reason: str,
):
    item.status = "skipped"
    item.last_error = (reason or "Skipped").strip()[:2000]
    db.commit()
    db.refresh(item)
    return item


def list_outbound_events(
    db: Session,
    *,
    limit: int = 100,
    channel: str | None = None,
    status: str | None = None,
    event_type: str | None = None,
):
    query = db.query(OutboundEvent)
    if channel:
        query = query.filter(OutboundEvent.channel == channel.strip().lower())
    if status:
        query = query.filter(OutboundEvent.status == _normalize_outbound_status(status))
    if event_type:
        query = query.filter(OutboundEvent.event_type == event_type.strip().lower())

    return query.order_by(OutboundEvent.created_at.desc()).limit(limit).all()


def get_outbound_summary_stats(db: Session):
    total_events = db.query(func.count(OutboundEvent.id)).scalar() or 0
    status_rows = (
        db.query(OutboundEvent.status, func.count(OutboundEvent.id))
        .group_by(OutboundEvent.status)
        .all()
    )
    channel_rows = (
        db.query(OutboundEvent.channel, func.count(OutboundEvent.id))
        .group_by(OutboundEvent.channel)
        .all()
    )
    sent_total = (
        db.query(func.count(OutboundEvent.id))
        .filter(OutboundEvent.status == "sent")
        .scalar()
        or 0
    )
    success_rate = 0.0
    if total_events:
        success_rate = round((float(sent_total) / float(total_events)) * 100.0, 1)

    return {
        "total_events": int(total_events),
        "sent_events": int(sent_total),
        "success_rate_percent": success_rate,
        "by_status": {row[0]: int(row[1]) for row in status_rows},
        "by_channel": {row[0]: int(row[1]) for row in channel_rows},
    }
