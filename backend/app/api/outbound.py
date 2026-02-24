from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.rbac import require_roles
from app.core.schemas import (
    OutboundEventListResponse,
    OutboundEventOut,
    OutboundSummaryStatsResponse,
)
from app.database.db import get_db
from app.database.repository import get_outbound_summary_stats, list_outbound_events

router = APIRouter(prefix="/outbound", tags=["outbound"])


@router.get("/events", response_model=OutboundEventListResponse)
def get_outbound_events(
    limit: int = Query(default=100, ge=1, le=500),
    channel: str | None = Query(default=None),
    status: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("manager", "admin")),
):
    try:
        items = list_outbound_events(
            db,
            limit=limit,
            channel=channel,
            status=status,
            event_type=event_type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return OutboundEventListResponse(
        items=[
            OutboundEventOut(
                id=str(item.id),
                channel=item.channel,
                event_type=item.event_type,
                fingerprint=item.fingerprint,
                status=item.status,
                attempts=item.attempts,
                last_error=item.last_error,
                first_attempt_at=item.first_attempt_at,
                last_attempt_at=item.last_attempt_at,
                sent_at=item.sent_at,
                created_at=item.created_at,
            )
            for item in items
        ]
    )


@router.get("/events/stats/summary", response_model=OutboundSummaryStatsResponse)
def get_outbound_events_summary(
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("manager", "admin")),
):
    return OutboundSummaryStatsResponse(**get_outbound_summary_stats(db))
