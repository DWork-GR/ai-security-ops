from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.rbac import require_roles
from app.core.schemas import (
    AssetDiscoveryListResponse,
    AssetDiscoveryOut,
    AssetListResponse,
    AssetOut,
    AssetUpsertRequest,
    ScanRunListResponse,
    ScanRunOut,
)
from app.database.db import get_db
from app.database.repository import (
    get_asset_by_ip,
    get_latest_scan_run_for_target,
    list_assets,
    list_open_ports_for_scan_run,
    list_scan_runs,
    upsert_asset,
)

router = APIRouter(prefix="/assets", tags=["assets"])


def _serialize_asset(item) -> AssetOut:
    return AssetOut(
        id=str(item.id),
        ip=item.ip,
        hostname=item.hostname,
        owner=item.owner,
        business_unit=item.business_unit,
        criticality=item.criticality,
        environment=item.environment,
        tags=item.tags,
        first_seen_at=item.first_seen_at,
        last_seen_at=item.last_seen_at,
    )


@router.get("", response_model=AssetListResponse)
def get_assets(
    limit: int = Query(default=200, ge=1, le=500),
    criticality: str | None = Query(default=None),
    environment: str | None = Query(default=None),
    search: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("analyst", "manager", "admin")),
):
    try:
        items = list_assets(
            db,
            limit=limit,
            criticality=criticality,
            environment=environment,
            search=search,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return AssetListResponse(items=[_serialize_asset(item) for item in items])


@router.get("/discovered", response_model=AssetDiscoveryListResponse)
def get_discovered_assets(
    limit: int = Query(default=50, ge=1, le=200),
    search: str | None = Query(default=None),
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("analyst", "manager", "admin")),
):
    items = list_assets(db, limit=limit, search=search)
    payload: list[AssetDiscoveryOut] = []
    for item in items:
        latest = get_latest_scan_run_for_target(db, item.ip)
        latest_ports = list_open_ports_for_scan_run(db, latest.id) if latest else []
        payload.append(
            AssetDiscoveryOut(
                ip=item.ip,
                hostname=item.hostname,
                criticality=item.criticality,
                environment=item.environment,
                last_seen_at=item.last_seen_at,
                latest_scan_at=latest.finished_at if latest else None,
                latest_scan_profile=latest.scan_profile if latest else None,
                latest_open_ports=latest_ports,
            )
        )
    return AssetDiscoveryListResponse(items=payload)


@router.put("", response_model=AssetOut)
def put_asset(
    payload: AssetUpsertRequest,
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("manager", "admin")),
):
    try:
        item = upsert_asset(
            db,
            ip=payload.ip,
            hostname=payload.hostname,
            owner=payload.owner,
            business_unit=payload.business_unit,
            criticality=payload.criticality,
            environment=payload.environment,
            tags=payload.tags,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _serialize_asset(item)


@router.get("/{ip}", response_model=AssetOut)
def get_asset(
    ip: str,
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("analyst", "manager", "admin")),
):
    item = get_asset_by_ip(db, ip)
    if not item:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _serialize_asset(item)


@router.get("/{ip}/scans", response_model=ScanRunListResponse)
def get_asset_scans(
    ip: str,
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("analyst", "manager", "admin")),
):
    asset = get_asset_by_ip(db, ip)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    runs = list_scan_runs(db, target_ip=ip, limit=limit)
    return ScanRunListResponse(
        items=[
            ScanRunOut(
                task_id=run.task_id,
                target_ip=run.target_ip,
                scan_profile=run.scan_profile,
                status=run.status,
                scanned_ports=run.scanned_ports,
                open_ports_count=run.open_ports_count,
                duration_ms=run.duration_ms,
                started_at=run.started_at,
                finished_at=run.finished_at,
                open_ports=list_open_ports_for_scan_run(db, run.id),
            )
            for run in runs
        ]
    )
