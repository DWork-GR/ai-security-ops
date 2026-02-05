from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.schemas import ChatRequest
from app.core.intent_router import detect_intent

from app.database.db import get_db
from app.database.repository import (
    get_cve_by_id,
    get_all_cves,
    get_critical_cves
)

router = APIRouter()


@router.post("/chat")
def process_message(
    request: ChatRequest,
    db: Session = Depends(get_db)
):
    intent, entities = detect_intent(request.message)

    # ===============================
    # 1️⃣ Конкретна CVE
    # ===============================
    if intent == "cve_lookup":
        cve_id = entities.get("cve_id")
        cve = get_cve_by_id(db, cve_id)

        if not cve:
            return {
                "type": "text",
                "message": f"❌ CVE {cve_id} не знайдено."
            }

        return {
            "type": "cves",
            "cves": [
                {
                    "cve_id": cve.cve_id,
                    "cvss": cve.cvss,
                    "severity": cve.severity,
                    "description": cve.description,
                    "mitigation": cve.mitigation
                }
            ]
        }

    # ===============================
    # 2️⃣ Всі уразливості
    # ===============================
    if intent == "list_cves":
        cves = get_all_cves(db)

        if not cves:
            return {
                "type": "text",
                "message": "ℹ️ База уразливостей порожня."
            }

        return {
            "type": "cves",
            "cves": [
                {
                    "cve_id": c.cve_id,
                    "cvss": c.cvss,
                    "severity": c.severity,
                    "description": c.description,
                    "mitigation": c.mitigation
                }
                for c in cves
            ]
        }

    # ===============================
    # 3️⃣ Критичні уразливості
    # ===============================
    if intent == "critical_cves":
        cves = get_critical_cves(db)

        if not cves:
            return {
                "type": "text",
                "message": "✅ Критичних уразливостей не виявлено."
            }

        return {
            "type": "cves",
            "cves": [
                {
                    "cve_id": c.cve_id,
                    "cvss": c.cvss,
                    "severity": c.severity,
                    "description": c.description,
                    "mitigation": c.mitigation
                }
                for c in cves
            ]
        }

    # ===============================
    # Fallback
    # ===============================
    return {
        "type": "text",
        "message": "ℹ️ Запит розпізнано, але логіка ще не реалізована."
    }
