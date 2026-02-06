from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.schemas import ChatRequest, ChatResponse
from app.core.intent_router import detect_intent

from app.database.db import get_db
from app.database.repository import (
    get_cve_by_id,
    get_all_cves,
    get_critical_cves
)

router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
def process_message(
    request: ChatRequest,
    db: Session = Depends(get_db)
):
    intent, entities = detect_intent(request.message)

    # 🔹 Критичні загрози
    if intent == "analyze_threats":
        cves = get_critical_cves(db)

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

    # 🔹 Конкретна CVE
    if intent == "cve_lookup":
        cve_id = entities.get("cve_id")
        cve = get_cve_by_id(db, cve_id)

        if not cve:
            return {"response": f"❌ CVE {cve_id} не знайдено."}

        return {
            "response": (
                f"{cve.cve_id}\n"
                f"CVSS {cve.cvss} ({cve.severity})\n\n"
                f"{cve.description}\n\n"
                f"{cve.mitigation}"
            )
        }

    return {
        "response": "ℹ️ Запит розпізнано, але обробка ще не реалізована."
    }

