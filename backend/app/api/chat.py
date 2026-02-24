from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.ai.expert_engine import analyze_alerts_expert
from app.ai.gemini_client import analyze_security_incidents
from app.core.intent_router import detect_intent
from app.core.schemas import ChatRequest
from app.database.db import get_db
from app.database.repository import (
    get_all_cves,
    get_critical_cves,
    get_cve_by_id,
)
from app.integrations.openvas.tasks import start_scan
from app.integrations.openvas.validator import is_valid_ip
from app.integrations.snort.analyzer import get_critical_alerts
from app.services.incident_service import correlate_incident

router = APIRouter()


def _serialize_cves(cves):
    return [
        {
            "cve_id": c.cve_id,
            "cvss": c.cvss,
            "severity": c.severity or "UNKNOWN",
            "description": c.description or "No description",
            "mitigation": c.mitigation or "No mitigation provided",
        }
        for c in cves
    ]


@router.post("/chat")
def process_message(request: ChatRequest, db: Session = Depends(get_db)):
    try:
        message = request.message.strip()
        intent, entities = detect_intent(message)

        if intent == "list_cves":
            cves = get_all_cves(db) or []
            if not cves:
                return {"type": "text", "message": "No CVE records found."}
            return {"type": "cves", "cves": _serialize_cves(cves)}

        if intent == "critical_cves":
            cves = get_critical_cves(db) or []
            if not cves:
                return {"type": "text", "message": "No critical CVEs found."}
            return {"type": "cves", "cves": _serialize_cves(cves)}

        if intent == "cve_lookup":
            cve_id = entities.get("cve_id")
            if not cve_id:
                return {"type": "text", "message": "CVE identifier is missing."}

            cve = get_cve_by_id(db, cve_id)
            if not cve:
                return {"type": "text", "message": f"CVE {cve_id} was not found."}

            return {
                "type": "text",
                "message": (
                    f"{cve.cve_id}\n"
                    f"CVSS: {cve.cvss} ({cve.severity})\n"
                    f"{cve.description}\n"
                    f"Mitigation: {cve.mitigation}"
                ),
            }

        if intent == "scan_ip":
            ip_address = entities.get("ip_address")
            if not ip_address:
                return {"type": "text", "message": "IP address is missing."}
            if not is_valid_ip(ip_address):
                return {"type": "text", "message": "Invalid IP address."}

            task = start_scan(ip_address)
            correlate_incident(
                db,
                source="openvas",
                message=f"OpenVAS scan started for {ip_address}",
                severity="MEDIUM",
            )
            return {
                "type": "text",
                "message": (
                    f"OpenVAS scan started.\n"
                    f"Task ID: {task['task_id']}\n"
                    f"Target: {task['target']}\n"
                    f"Status: {task['status']}"
                ),
            }

        if intent == "analyze_threats":
            alerts = get_critical_alerts()
            if not alerts:
                return {"type": "text", "message": "No critical Snort alerts found."}

            alert_messages = [alert["message"] for alert in alerts]
            created_count = 0
            updated_count = 0
            for alert_message in alert_messages:
                _, created = correlate_incident(
                    db,
                    source="snort",
                    message=alert_message,
                    severity="HIGH",
                )
                if created:
                    created_count += 1
                else:
                    updated_count += 1

            analysis = analyze_alerts_expert(alert_messages)
            llm_analysis = analyze_security_incidents(alert_messages)
            return {
                "type": "text",
                "message": (
                    f"Incidents: created={created_count}, updated={updated_count}\n\n"
                    f"{analysis}\n\n"
                    f"LLM enrichment:\n{llm_analysis}"
                ),
            }

        return {
            "type": "text",
            "message": (
                "Unknown command.\n"
                "Try:\n"
                "- show cves\n"
                "- show critical cves\n"
                "- scan 192.168.1.1\n"
                "- CVE-2021-44228\n"
                "- analyze threats"
            ),
        }

    except Exception as exc:
        print("CHAT ERROR:", exc)
        return {"type": "text", "message": "Server error. Check backend logs."}
