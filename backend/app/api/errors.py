from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.rbac import require_roles
from app.core.schemas import ErrorEventListResponse, ErrorEventOut, ErrorSummaryStatsResponse
from app.database.db import get_db
from app.database.repository import get_error_summary_stats, list_error_events
from app.utils.sanitization import sanitize_sensitive_text

router = APIRouter(prefix="/errors", tags=["errors"])


@router.get("", response_model=ErrorEventListResponse)
def get_errors(
    limit: int = Query(default=100, ge=1, le=500),
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    error_type: str | None = Query(default=None),
    search: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("analyst", "manager", "admin")),
):
    try:
        items = list_error_events(
            db,
            limit=limit,
            source=source,
            severity=severity,
            error_type=error_type,
            search=search,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return ErrorEventListResponse(
        items=[
                ErrorEventOut(
                    id=str(item.id),
                    source=item.source,
                    operation=item.operation,
                    error_type=item.error_type,
                    message=sanitize_sensitive_text(item.message, max_len=1000),
                    severity=item.severity,
                    fingerprint=item.fingerprint,
                    occurrences=item.occurrences,
                    context=sanitize_sensitive_text(item.context, max_len=1000) if item.context else None,
                    first_seen_at=item.first_seen_at,
                    last_seen_at=item.last_seen_at,
                )
            for item in items
        ]
    )


@router.get("/stats/summary", response_model=ErrorSummaryStatsResponse)
def get_errors_summary(
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("manager", "admin")),
):
    return ErrorSummaryStatsResponse(**get_error_summary_stats(db))
