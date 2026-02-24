import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.rbac import require_roles
from app.core.schemas import (
    ScanJobCreateRequest,
    ScanJobListResponse,
    ScanJobOut,
)
from app.database.db import get_db
from app.services.scan_job_service import (
    enqueue_scan_job,
    execute_scan_job,
    find_scan_jobs,
    get_scan_job,
)

router = APIRouter(prefix="/scans", tags=["scans"])


def _parse_result_summary(raw: str | None):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


def _serialize_scan_job(item) -> ScanJobOut:
    return ScanJobOut(
        id=str(item.id),
        target_ip=item.target_ip,
        scan_type=item.scan_type,
        status=item.status,
        requested_by=item.requested_by,
        attempts=item.attempts,
        result_summary=_parse_result_summary(item.result_summary),
        last_error=item.last_error,
        created_at=item.created_at,
        started_at=item.started_at,
        finished_at=item.finished_at,
    )


@router.post("/jobs", response_model=ScanJobOut)
def create_scan_job(
    payload: ScanJobCreateRequest,
    db: Session = Depends(get_db),
    role: str = Depends(require_roles("analyst", "manager", "admin")),
):
    try:
        item = enqueue_scan_job(
            db,
            target_ip=payload.target_ip,
            scan_type=payload.scan_type,
            requested_by=payload.requested_by or role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _serialize_scan_job(item)


@router.get("/jobs", response_model=ScanJobListResponse)
def list_scan_jobs(
    limit: int = Query(default=100, ge=1, le=500),
    status: str | None = Query(default=None),
    scan_type: str | None = Query(default=None),
    target_ip: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("analyst", "manager", "admin")),
):
    try:
        items = find_scan_jobs(
            db,
            limit=limit,
            status=status,
            scan_type=scan_type,
            target_ip=target_ip,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ScanJobListResponse(items=[_serialize_scan_job(item) for item in items])


@router.get("/jobs/{job_id}", response_model=ScanJobOut)
def get_scan_job_by_id(
    job_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("analyst", "manager", "admin")),
):
    item = get_scan_job(db, job_id)
    if not item:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return _serialize_scan_job(item)


@router.post("/jobs/{job_id}/run", response_model=ScanJobOut)
def run_scan_job_now(
    job_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("manager", "admin")),
):
    try:
        item = execute_scan_job(db, job_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return _serialize_scan_job(item)
