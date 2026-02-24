from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.schemas import IncidentListResponse, IncidentOut
from app.database.db import get_db
from app.database.repository import list_incidents

router = APIRouter(tags=["incidents"])


@router.get("/incidents", response_model=IncidentListResponse)
def get_incidents(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    incidents = list_incidents(db, limit=limit)
    items = [
        IncidentOut(
            id=str(incident.id),
            source=incident.source,
            message=incident.message,
            severity=incident.severity,
            status=incident.status,
            detected_at=incident.detected_at,
        )
        for incident in incidents
    ]
    return IncidentListResponse(items=items)
