from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.rbac import require_roles
from app.core.schemas import CVEListResponse, CVEOut, CVESeedResponse, NvdImportRequest, NvdImportResponse
from app.database.db import get_db
from app.database.real_world_threats import REAL_WORLD_THREATS
from app.database.repository import get_cve_by_id, search_cves, upsert_cves
from app.services.error_service import record_exception
from app.services.nvd_import_service import import_nvd_json

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


def _serialize_cve(item) -> CVEOut:
    return CVEOut(
        cve_id=item.cve_id,
        cvss=item.cvss,
        severity=item.severity,
        description=item.description,
        mitigation=item.mitigation,
    )


@router.get("/cves/search", response_model=CVEListResponse)
def search_knowledge_cves(
    q: str | None = Query(default=None, min_length=1),
    severity: str | None = Query(default=None),
    min_cvss: float | None = Query(default=None, ge=0, le=10),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("analyst", "manager", "admin")),
):
    try:
        items = search_cves(
            db,
            query=q,
            severity=severity,
            min_cvss=min_cvss,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    payload = [_serialize_cve(item) for item in items]
    return CVEListResponse(total=len(payload), items=payload)


@router.get("/cves/{cve_id}", response_model=CVEOut)
def get_knowledge_cve(
    cve_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("analyst", "manager", "admin")),
):
    item = get_cve_by_id(db, cve_id.upper().strip())
    if not item:
        raise HTTPException(status_code=404, detail="CVE not found")
    return _serialize_cve(item)


@router.post("/cves/import/nvd", response_model=NvdImportResponse)
def import_knowledge_from_nvd(
    payload: NvdImportRequest,
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("manager", "admin")),
):
    try:
        result = import_nvd_json(
            db,
            file_path=payload.file_path,
            default_mitigation=payload.default_mitigation,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        record_exception(
            db,
            source="knowledge",
            operation="import_nvd",
            exc=exc,
            severity="HIGH",
            context={"file_path": payload.file_path},
        )
        raise HTTPException(status_code=500, detail="NVD import failed") from exc

    return NvdImportResponse(**result)


@router.post("/cves/seed/real-world", response_model=CVESeedResponse)
def seed_real_world_threats(
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("manager", "admin")),
):
    try:
        created, updated = upsert_cves(db, REAL_WORLD_THREATS)
    except Exception as exc:
        record_exception(
            db,
            source="knowledge",
            operation="seed_real_world",
            exc=exc,
            severity="HIGH",
            context={"records": len(REAL_WORLD_THREATS)},
        )
        raise HTTPException(status_code=500, detail="Real-world threat seed failed") from exc

    return CVESeedResponse(
        imported_total=len(REAL_WORLD_THREATS),
        created=created,
        updated=updated,
        source="real-world-curated-pack",
    )
