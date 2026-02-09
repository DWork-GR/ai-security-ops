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
        message = request.message.lower()
        intent, entities = detect_intent(message)

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
            except Exception as e:
                print("CHAT ERROR:", e)
                return {
                    "type": "text",
                    "message": "❌ Помилка на сервері"
            }

        # 🔹 Конкретна CVE
        if intent == "cve_lookup":
            cve_id = entities.get("cve_id")
            cve = get_cve_by_id(db, cve_id)

            if not cve:
                return {
                    "type": "text",
                    "message": f"❌ CVE {cve_id} не знайдено."
                }

            return {
                "type": "text",
                "message": (
                    f"{cve.cve_id}\n"
                    f"CVSS {cve.cvss} ({cve.severity})\n\n"
                    f"{cve.description}\n\n"
                    f"{cve.mitigation}"
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
            "message": "❌ Помилка на сервері"
        }
