from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.schemas import ChatRequest
from app.core.intent_router import detect_intent
from app.database.db import get_db
from app.database.repository import (
    get_cve_by_id,
    get_critical_cves
)

router = APIRouter()


@router.post("/chat")
def process_message(
    request: ChatRequest,
    db: Session = Depends(get_db)
):
    try:
        # нормалізуємо повідомлення
        message = request.message.strip().lower()
        intent, entities = detect_intent(message)

        # 🔹 КРИТИЧНІ ЗАГРОЗИ
        if intent == "analyze_threats":
            cves = get_critical_cves(db) or []

            if not cves:
                return {
                    "type": "text",
                    "message": "ℹ️ Критичних вразливостей не знайдено."
                }

            return {
                "type": "cves",
                "cves": [
                    {
                        "cve_id": c.cve_id,
                        "cvss": c.cvss,
                        "severity": c.severity or "UNKNOWN",
                        "description": c.description or "Опис відсутній",
                        "mitigation": c.mitigation or "Рекомендації відсутні"
                    }
                    for c in cves
                ]
            }

        # 🔹 ПОШУК CVE
        if intent == "cve_lookup":
            cve_id = entities.get("cve_id")

            if not cve_id:
                return {
                    "type": "text",
                    "message": "❌ Не вказано CVE ідентифікатор."
                }

            cve = get_cve_by_id(db, cve_id)

            if not cve:
                return {
                    "type": "text",
                    "message": f"❌ CVE **{cve_id}** не знайдено."
                }

            return {
                "type": "text",
                "message": (
                    f"**{cve.cve_id}**\n"
                    f"CVSS: {cve.cvss} ({cve.severity})\n\n"
                    f"{cve.description}\n\n"
                    f"🛠 **Рекомендація:**\n{cve.mitigation}"
                )
            }

        # 🔹 DEFAULT
        return {
            "type": "text",
            "message": (
                "🤖 **Я не розпізнав запит**\n\n"
                "Спробуй одну з команд:\n"
                "• **Критичні загрози** — перегляд активних CVE\n"
                "• **Скануй 192.168.1.1** — запуск перевірки\n"
                "• **CVE-2023-XXXX** — інформація про вразливість"
            )
        }

    except Exception as e:
        print("CHAT ERROR:", e)
        return {
            "type": "text",
            "message": "❌ Помилка на сервері. Перевір логи."
        }
