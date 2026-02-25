import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from app.api.rbac import RBAC_ENABLED, RBAC_KEY_TO_ROLE
from app.config import STREAM_ALLOW_QUERY_USER_KEY
from app.database.db import SessionLocal
from app.database.repository import (
    get_error_summary_stats,
    get_incident_summary_stats,
    get_latest_scan_run_for_target,
    list_assets,
    list_error_events,
    list_incidents,
    list_open_ports_for_scan_run,
    list_scan_jobs,
)
from app.services.incident_service import calculate_risk_score, infer_asset_from_text
from app.services.attack_mapping_service import infer_attack_mapping

router = APIRouter(prefix="/stream", tags=["stream"])


def _iso(value: datetime | None) -> str | None:
    if not value:
        return None
    return value.isoformat()


def _parse_summary(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


def _resolve_stream_role(*, header_key: str | None, query_key: str | None) -> str:
    if not RBAC_ENABLED:
        return "admin"

    api_key = (header_key or "").strip()
    if not api_key and query_key and not STREAM_ALLOW_QUERY_USER_KEY:
        raise HTTPException(
            status_code=401,
            detail="Query auth is disabled for stream. Use X-User-Key header",
        )
    if not api_key and STREAM_ALLOW_QUERY_USER_KEY:
        api_key = (query_key or "").strip()

    if not api_key:
        if STREAM_ALLOW_QUERY_USER_KEY:
            raise HTTPException(status_code=401, detail="X-User-Key or user_key is required")
        raise HTTPException(status_code=401, detail="X-User-Key is required")

    role = RBAC_KEY_TO_ROLE.get(api_key)
    if not role:
        raise HTTPException(status_code=401, detail="Invalid user key")
    return role


def _ensure_allowed_role(role: str, allowed_roles: set[str]) -> None:
    if role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Insufficient role")


def _build_snapshot(limit: int) -> dict:
    with SessionLocal() as db:
        incident_stats = get_incident_summary_stats(db)
        error_stats = get_error_summary_stats(db)
        incidents = list_incidents(db, limit=limit)
        errors = list_error_events(db, limit=limit)
        jobs = list_scan_jobs(db, limit=limit)
        assets = list_assets(db, limit=limit)

        incident_rows = [
            {
                "id": str(item.id),
                "source": item.source,
                "severity": item.severity,
                "status": item.status,
                "message": item.message,
                "detected_at": _iso(item.detected_at),
                "risk_score": calculate_risk_score(
                    severity=item.severity,
                    source=item.source,
                    status=item.status,
                ),
                "asset": infer_asset_from_text(item.message),
                **infer_attack_mapping(source=item.source, message=item.message),
            }
            for item in incidents
        ]

        error_rows = [
            {
                "id": str(item.id),
                "source": item.source,
                "operation": item.operation,
                "error_type": item.error_type,
                "severity": item.severity,
                "occurrences": int(item.occurrences or 0),
                "last_seen_at": _iso(item.last_seen_at),
            }
            for item in errors
        ]

        scan_rows = [
            {
                "id": str(item.id),
                "target_ip": item.target_ip,
                "scan_type": item.scan_type,
                "status": item.status,
                "attempts": int(item.attempts or 0),
                "created_at": _iso(item.created_at),
                "started_at": _iso(item.started_at),
                "finished_at": _iso(item.finished_at),
                "result_summary": _parse_summary(item.result_summary),
                "last_error": item.last_error,
            }
            for item in jobs
        ]

        asset_rows = []
        for item in assets:
            latest = get_latest_scan_run_for_target(db, item.ip)
            latest_open_ports = list_open_ports_for_scan_run(db, latest.id) if latest else []
            asset_rows.append(
                {
                    "ip": item.ip,
                    "hostname": item.hostname,
                    "criticality": item.criticality,
                    "environment": item.environment,
                    "last_seen_at": _iso(item.last_seen_at),
                    "latest_scan_at": _iso(latest.finished_at) if latest else None,
                    "latest_scan_profile": latest.scan_profile if latest else None,
                    "latest_open_ports": latest_open_ports,
                }
            )

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incident_stats": incident_stats,
        "error_stats": error_stats,
        "incidents": incident_rows,
        "errors": error_rows,
        "scan_jobs": scan_rows,
        "assets": asset_rows,
    }


@router.get("/soc-live")
async def stream_soc_live(
    request: Request,
    limit: int = Query(default=8, ge=1, le=50),
    interval_sec: float = Query(default=3.0, ge=1.0, le=20.0),
    once: bool = Query(default=False),
    user_key: str | None = Query(default=None),
    x_user_key: str | None = Header(default=None, alias="X-User-Key"),
):
    role = _resolve_stream_role(header_key=x_user_key, query_key=user_key)
    _ensure_allowed_role(role, {"analyst", "manager", "admin"})

    async def event_generator():
        while True:
            if await request.is_disconnected():
                break

            payload = _build_snapshot(limit)
            yield f"event: snapshot\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

            if once:
                break
            await asyncio.sleep(interval_sec)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
