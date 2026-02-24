from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import require_integration_api_key
from app.core.schemas import (
    OpenVASActiveScanRequest,
    OpenVASActiveScanResponse,
    OpenVASScanRequest,
    OpenVASScanResponse,
    SnortAlertsIn,
)
from app.database.db import get_db
from app.integrations.openvas.tasks import start_scan
from app.integrations.openvas.validator import is_valid_ip
from app.services.error_service import record_exception
from app.services.incident_service import correlate_incident
from app.services.scan_service import run_active_scan

router = APIRouter(
    prefix="/integrations",
    tags=["integrations"],
    dependencies=[Depends(require_integration_api_key)],
)


def _priority_to_severity(priority: int) -> str:
    if priority <= 1:
        return "CRITICAL"
    if priority == 2:
        return "HIGH"
    if priority == 3:
        return "MEDIUM"
    return "LOW"


@router.post("/openvas/scan", response_model=OpenVASScanResponse)
def openvas_scan(payload: OpenVASScanRequest, db: Session = Depends(get_db)):
    if not is_valid_ip(payload.target):
        raise HTTPException(status_code=400, detail="Invalid target IP address")
    try:
        task = start_scan(payload.target)
        correlate_incident(
            db,
            source="openvas",
            message=f"OpenVAS scan started for {payload.target}",
            severity="MEDIUM",
            asset=payload.target,
            signature="openvas_scan_started",
            actor_role="integration",
        )
        return task
    except Exception as exc:
        record_exception(
            db,
            source="openvas",
            operation="start_scan",
            exc=exc,
            severity="MEDIUM",
            context={"target": payload.target},
        )
        raise HTTPException(status_code=500, detail="Failed to start scan") from exc


@router.post("/openvas/scan/active", response_model=OpenVASActiveScanResponse)
def openvas_active_scan(payload: OpenVASActiveScanRequest, db: Session = Depends(get_db)):
    if not is_valid_ip(payload.target):
        raise HTTPException(status_code=400, detail="Invalid target IP address")

    try:
        result = run_active_scan(
            db,
            target=payload.target,
            ports=payload.ports,
            timeout_ms=payload.timeout_ms,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        record_exception(
            db,
            source="openvas",
            operation="active_scan",
            exc=exc,
            severity="HIGH",
            context={"target": payload.target},
        )
        raise HTTPException(status_code=500, detail="Active scan execution failed") from exc

    return OpenVASActiveScanResponse(**result)


@router.post("/snort/alerts")
def ingest_snort_alerts(payload: SnortAlertsIn, db: Session = Depends(get_db)):
    incidents_created = 0
    incidents_updated = 0

    try:
        for alert in payload.alerts:
            severity = _priority_to_severity(alert.priority)
            _, created = correlate_incident(
                db,
                source="snort",
                message=alert.message,
                severity=severity,
                asset=alert.dst_ip or alert.src_ip,
                signature=alert.message,
                actor_role="integration",
            )
            if created:
                incidents_created += 1
            else:
                incidents_updated += 1
    except Exception as exc:
        record_exception(
            db,
            source="snort",
            operation="ingest_alerts",
            exc=exc,
            severity="HIGH",
            context={"accepted": len(payload.alerts)},
        )
        raise HTTPException(status_code=500, detail="Failed to ingest Snort alerts") from exc

    return {
        "accepted": len(payload.alerts),
        "incidents_created": incidents_created,
        "incidents_updated": incidents_updated,
    }
