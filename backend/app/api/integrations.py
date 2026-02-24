from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies import require_integration_api_key
from app.core.schemas import (
    OpenVASScanRequest,
    OpenVASScanResponse,
    SnortAlertsIn,
)
from app.database.db import get_db
from app.integrations.openvas.tasks import start_scan
from app.integrations.openvas.validator import is_valid_ip
from app.services.incident_service import correlate_incident

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
    task = start_scan(payload.target)
    correlate_incident(
        db,
        source="openvas",
        message=f"OpenVAS scan started for {payload.target}",
        severity="MEDIUM",
    )
    return task


@router.post("/snort/alerts")
def ingest_snort_alerts(payload: SnortAlertsIn, db: Session = Depends(get_db)):
    incidents_created = 0
    incidents_updated = 0

    for alert in payload.alerts:
        severity = _priority_to_severity(alert.priority)
        _, created = correlate_incident(
            db,
            source="snort",
            message=alert.message,
            severity=severity,
        )
        if created:
            incidents_created += 1
        else:
            incidents_updated += 1

    return {
        "accepted": len(payload.alerts),
        "incidents_created": incidents_created,
        "incidents_updated": incidents_updated,
    }
