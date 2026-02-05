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

    # 1️⃣ Конкретная CVE
    if intent == "cve_lookup":
        cve_id = entities.get("cve_id")
        cve = get_cve_by_id(db, cve_id)

        if not cve:
            return ChatResponse(
                response=f"❌ CVE {cve_id} не знайдено.",
                intent=intent,
                entities=entities
            )

        return ChatResponse(
            response=(
                f"🛡 {cve.cve_id}\n"
                f"CVSS: {cve.cvss} ({cve.severity})\n\n"
                f"{cve.description}\n\n"
                f"🔧 Mitigation:\n{cve.mitigation}"
            ),
            intent=intent,
            entities=entities
        )

    # 2️⃣ Все уязвимости
    if intent == "list_cves":
        cves = get_all_cves(db)

        if not cves:
            return ChatResponse(
                response="ℹ️ База уразливостей порожня.",
                intent=intent,
                entities=entities
            )

        text = "📋 **Всі уразливості:**\n\n"
        for cve in cves:
            text += f"- {cve.cve_id} | CVSS {cve.cvss} | {cve.severity}\n"

        return ChatResponse(
            response=text,
            intent=intent,
            entities=entities
        )

    # 3️⃣ Критические
    if intent == "analyze_threats":
        cves = get_critical_cves()

    if not cves:
        return ChatResponse(
            response="✅ Критичних загроз не виявлено.",
            intent=intent,
            entities={}
        )

    # Формируем человекочитаемый ответ
    lines = ["🚨 **Критичні загрози у системі:**\n"]

    for cve in cves:
        lines.append(
            f"- {cve.cve_id} | CVSS {cve.cvss} | {cve.description}"
        )

    return ChatResponse(
        response="\n".join(lines),
        intent=intent,
        entities={}
    )   


