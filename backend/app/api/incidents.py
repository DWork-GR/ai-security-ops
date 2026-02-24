from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.rbac import require_roles
from app.core.schemas import (
    IncidentAuditLogListResponse,
    IncidentAuditLogOut,
    IncidentListResponse,
    IncidentOut,
    IncidentStatusUpdateRequest,
    IncidentStatusUpdateResponse,
    IncidentSummaryStatsResponse,
)
from app.database.db import get_db
from app.database.repository import (
    create_incident_audit_log,
    get_incident_by_id,
    get_incident_summary_stats,
    list_incident_audit_logs,
    list_incidents,
    update_incident_status,
)
from app.services.incident_service import calculate_risk_score, infer_asset_from_text

router = APIRouter(tags=["incidents"])


def _serialize_incident(incident) -> IncidentOut:
    return IncidentOut(
        id=str(incident.id),
        source=incident.source,
        message=incident.message,
        severity=incident.severity,
        status=incident.status,
        detected_at=incident.detected_at,
        risk_score=calculate_risk_score(
            severity=incident.severity,
            source=incident.source,
            status=incident.status,
        ),
        asset=infer_asset_from_text(incident.message),
    )


@router.get("/incidents/stats/summary", response_model=IncidentSummaryStatsResponse)
def get_incidents_summary(
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("analyst", "manager", "admin")),
):
    return IncidentSummaryStatsResponse(**get_incident_summary_stats(db))


@router.get("/incidents", response_model=IncidentListResponse)
def get_incidents(
    limit: int = Query(default=100, ge=1, le=500),
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    search: str | None = Query(default=None),
    min_risk: float | None = Query(default=None, ge=0, le=100),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("analyst", "manager", "admin")),
):
    try:
        incidents = list_incidents(
            db,
            limit=limit,
            source=source,
            severity=severity,
            status=status,
            search=search,
            date_from=date_from,
            date_to=date_to,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    serialized = [_serialize_incident(incident) for incident in incidents]
    if min_risk is not None:
        serialized = [item for item in serialized if item.risk_score >= min_risk]
    return IncidentListResponse(items=serialized)


@router.get("/incidents/{incident_id}", response_model=IncidentStatusUpdateResponse)
def get_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("analyst", "manager", "admin")),
):
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentStatusUpdateResponse(item=_serialize_incident(incident))


@router.get("/incidents/{incident_id}/audit", response_model=IncidentAuditLogListResponse)
def get_incident_audit(
    incident_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("manager", "admin")),
):
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    logs = list_incident_audit_logs(db, incident_id, limit=limit)
    return IncidentAuditLogListResponse(
        items=[
            IncidentAuditLogOut(
                id=str(log.id),
                action=log.action,
                old_status=log.old_status,
                new_status=log.new_status,
                actor_role=log.actor_role,
                actor_id=log.actor_id,
                details=log.details,
                created_at=log.created_at,
            )
            for log in logs
        ]
    )


@router.patch("/incidents/{incident_id}/status", response_model=IncidentStatusUpdateResponse)
def patch_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdateRequest,
    db: Session = Depends(get_db),
    role: str = Depends(require_roles("analyst", "manager", "admin")),
):
    incident = get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = incident.status
    high_privilege_statuses = {"mitigated", "closed", "false_positive"}
    target_status = payload.status.lower().strip()
    if target_status in high_privilege_statuses and role not in {"manager", "admin"}:
        raise HTTPException(
            status_code=403,
            detail="Only manager/admin can set status to mitigated/closed/false_positive",
        )

    try:
        updated = update_incident_status(db, incident, payload.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    create_incident_audit_log(
        db,
        incident_id=updated.id,
        action="status_changed",
        old_status=old_status,
        new_status=updated.status,
        actor_role=role,
        details="Manual status update via API",
    )
    return IncidentStatusUpdateResponse(item=_serialize_incident(updated))
