import json

from sqlalchemy.orm import Session

from app.database.repository import (
    create_scan_job,
    get_next_queued_scan_job,
    get_scan_job_by_id,
    list_scan_jobs,
    mark_scan_job_completed,
    mark_scan_job_failed,
    mark_scan_job_running,
)
from app.integrations.openvas.validator import is_valid_ip
from app.services.error_service import record_exception
from app.services.scan_service import run_active_scan

QUICK_SCAN_PORTS = [22, 80, 443, 3389, 3306, 5432]


def enqueue_scan_job(
    db: Session,
    *,
    target_ip: str,
    scan_type: str,
    requested_by: str | None = None,
):
    if not is_valid_ip(target_ip):
        raise ValueError("Invalid target IP address")
    return create_scan_job(
        db,
        target_ip=target_ip,
        scan_type=scan_type,
        requested_by=requested_by,
    )


def get_scan_job(db: Session, job_id: str):
    return get_scan_job_by_id(db, job_id)


def find_scan_jobs(
    db: Session,
    *,
    limit: int = 100,
    status: str | None = None,
    scan_type: str | None = None,
    target_ip: str | None = None,
):
    return list_scan_jobs(
        db,
        limit=limit,
        status=status,
        scan_type=scan_type,
        target_ip=target_ip,
    )


def _compact_scan_result(result: dict) -> dict:
    return {
        "task_id": result.get("task_id"),
        "scanner": result.get("scanner"),
        "target": result.get("target"),
        "status": result.get("status"),
        "scan_profile": result.get("scan_profile"),
        "duration_ms": result.get("duration_ms"),
        "open_ports": result.get("open_ports", []),
        "new_open_ports": result.get("new_open_ports", []),
        "closed_open_ports": result.get("closed_open_ports", []),
        "findings_count": len(result.get("findings", [])),
        "incidents_created": result.get("incidents_created", 0),
        "incidents_updated": result.get("incidents_updated", 0),
    }


def _run_profile(db: Session, *, target_ip: str, scan_type: str) -> dict:
    scan_kind = (scan_type or "").lower().strip()

    if scan_kind == "quick":
        return run_active_scan(
            db,
            target=target_ip,
            source="nmap",
            ports=QUICK_SCAN_PORTS,
            timeout_ms=180,
        )
    if scan_kind == "discovery":
        return run_active_scan(
            db,
            target=target_ip,
            source="nmap",
        )
    if scan_kind == "vulnerability":
        return run_active_scan(
            db,
            target=target_ip,
            source="openvas",
        )
    if scan_kind == "full":
        discovery = run_active_scan(
            db,
            target=target_ip,
            source="nmap",
        )
        vulnerability = run_active_scan(
            db,
            target=target_ip,
            source="openvas",
        )
        return {
            "mode": "full",
            "target": target_ip,
            "steps": [
                _compact_scan_result(discovery),
                _compact_scan_result(vulnerability),
            ],
            "combined_open_ports": sorted(
                set(discovery.get("open_ports", [])) | set(vulnerability.get("open_ports", []))
            ),
            "total_findings_count": len(discovery.get("findings", []))
            + len(vulnerability.get("findings", [])),
            "total_incidents_created": int(discovery.get("incidents_created", 0))
            + int(vulnerability.get("incidents_created", 0)),
            "total_incidents_updated": int(discovery.get("incidents_updated", 0))
            + int(vulnerability.get("incidents_updated", 0)),
        }

    raise ValueError("Unsupported scan type")


def execute_scan_job(db: Session, job_id: str):
    job = get_scan_job_by_id(db, job_id)
    if not job:
        raise ValueError("Scan job not found")

    if job.status == "running":
        return job
    if job.status == "completed":
        return job
    if job.status == "cancelled":
        return job

    mark_scan_job_running(db, job)

    try:
        summary = _run_profile(
            db,
            target_ip=job.target_ip,
            scan_type=job.scan_type,
        )
        payload = json.dumps(summary, ensure_ascii=False, separators=(",", ":"))
        return mark_scan_job_completed(db, job, result_summary=payload)
    except Exception as exc:
        mark_scan_job_failed(db, job, error_message=str(exc))
        record_exception(
            db,
            source="scan_jobs",
            operation="execute_job",
            exc=exc,
            severity="HIGH",
            context={"job_id": job.id, "target_ip": job.target_ip, "scan_type": job.scan_type},
        )
        return job


def execute_next_queued_scan_job(db: Session):
    next_job = get_next_queued_scan_job(db)
    if not next_job:
        return None
    return execute_scan_job(db, str(next_job.id))
