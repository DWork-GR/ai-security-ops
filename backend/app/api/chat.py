from fastapi import APIRouter

from app.core.schemas import ChatRequest, ChatResponse
from app.core.intent_router import detect_intent

from app.database.repository import get_cve_by_id
from app.integrations.snort.analyzer import get_critical_alerts
from app.integrations.openvas.validator import is_valid_ip
from app.integrations.openvas.tasks import start_scan

from app.ai.expert_engine import analyze_alerts_expert

from fastapi import Depends
from sqlalchemy.orm import Session
from app.database.db import get_db



router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
def process_message(
    request: ChatRequest,
    db: Session = Depends(get_db)
):
    intent, entities = detect_intent(request.message)

    if intent == "cve_lookup":
        cve_id = entities.get("cve_id")

        if not cve_id:
            return ChatResponse(
                response="❌ Не вказано ідентифікатор CVE.",
                intent=intent,
                entities=entities
            )

        cve = get_cve_by_id(db, cve_id)

        if not cve:
            return ChatResponse(
                response=f"❌ Уразливість {cve_id} не знайдена у базі знань.",
                intent=intent,
                entities=entities
            )

        response_text = (
            f"🛡 {cve.id}\n"
            f"CVSS: {cve.cvss}\n\n"
            f"{cve.description}\n\n"
            f"🔧 Mitigation:\n{cve.mitigation}"
        )

        return ChatResponse(
            response=response_text,
            intent=intent,
            entities=entities
        )

    return ChatResponse(
        response=f"ℹ️ Виявлено намір: {intent}",
        intent=intent,
        entities=entities
    )

