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
    get_error_summary_stats,
    get_incident_summary_stats,
    get_platform_overview_stats,
    list_error_events,
    list_incidents,
    search_cves,
)
from app.integrations.openvas.validator import is_valid_ip
from app.integrations.snort.analyzer import get_critical_alerts
from app.services.error_service import record_exception
from app.services.incident_service import correlate_incident
from app.services.scan_service import run_active_scan

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


def _format_incident_rows(incidents) -> str:
    if not incidents:
        return "No incidents found."

    lines = ["[Incidents] Latest SOC incidents:"]
    for incident in incidents:
        lines.append(
            f"- {incident.detected_at.isoformat()} | {incident.severity} | "
            f"{incident.status} | {incident.source} | {incident.message}"
        )
    return "\n".join(lines)


def _format_incident_stats(stats: dict) -> str:
    lines = [
        "[SOC KPI Snapshot]",
        f"- Total incidents: {stats['total_incidents']}",
        f"- Open incidents: {stats['open_incidents']}",
        f"- Critical open incidents: {stats['critical_open_incidents']}",
        f"- Incidents in last 24h: {stats['incidents_last_24h']}",
        "",
        "By severity:",
    ]
    for severity, count in sorted(stats["by_severity"].items()):
        lines.append(f"- {severity}: {count}")

    lines.append("")
    lines.append("By source:")
    for source, count in sorted(stats["by_source"].items()):
        lines.append(f"- {source}: {count}")

    lines.append("")
    lines.append("By status:")
    for status, count in sorted(stats["by_status"].items()):
        lines.append(f"- {status}: {count}")

    return "\n".join(lines)


def _format_active_scan_result(result: dict) -> str:
    lines = [
        "[EN] Active Scan",
        f"- Task ID: {result['task_id']}",
        f"- Target: {result['target']}",
        f"- Status: {result['status']}",
        f"- Scan profile: {result['scan_profile']}",
        f"- Scanned ports: {result['scanned_ports']}",
        f"- Open ports: {', '.join(str(p) for p in result['open_ports']) if result['open_ports'] else 'none'}",
        f"- New open ports vs baseline: {', '.join(str(p) for p in result['new_open_ports']) if result['new_open_ports'] else 'none'}",
        f"- Closed open ports vs baseline: {', '.join(str(p) for p in result['closed_open_ports']) if result['closed_open_ports'] else 'none'}",
        f"- Findings: {len(result['findings'])}",
        f"- Incidents: created={result['incidents_created']}, updated={result['incidents_updated']}",
        "",
        "[UK] Активне Сканування",
        f"- Ціль: {result['target']}",
        f"- Відкриті порти: {', '.join(str(p) for p in result['open_ports']) if result['open_ports'] else 'немає'}",
        f"- Нові порти проти baseline: {', '.join(str(p) for p in result['new_open_ports']) if result['new_open_ports'] else 'немає'}",
        f"- Закриті порти проти baseline: {', '.join(str(p) for p in result['closed_open_ports']) if result['closed_open_ports'] else 'немає'}",
        f"- Знахідок: {len(result['findings'])}",
    ]

    if result["findings"]:
        lines.append("")
        lines.append("Top findings:")
        for finding in result["findings"][:5]:
            cves = ", ".join(finding["cve_references"]) if finding["cve_references"] else "n/a"
            lines.append(
                f"- {finding['severity']} | {finding['service']}:{finding['port']} | "
                f"risk={finding['risk_score']} | CVEs={cves}"
            )
    return "\n".join(lines)


def _format_error_rows(items) -> str:
    if not items:
        return "No error events found."
    lines = ["[Errors] Latest error events:"]
    for item in items:
        lines.append(
            f"- {item.last_seen_at.isoformat()} | {item.severity} | {item.source}.{item.operation} | "
            f"{item.error_type} | count={item.occurrences}"
        )
    return "\n".join(lines)


def _format_error_stats(stats: dict) -> str:
    lines = [
        "[Error Stats]",
        f"- Total unique errors: {stats['total_errors']}",
        f"- Total occurrences: {stats['total_occurrences']}",
        f"- Errors in last 24h: {stats['errors_last_24h']}",
        "",
        "By severity:",
    ]
    for key, value in sorted(stats["by_severity"].items()):
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append("By source:")
    for key, value in sorted(stats["by_source"].items()):
        lines.append(f"- {key}: {value}")
    return "\n".join(lines)


def _format_help_menu(topic: str | None = None) -> str:
    if topic == "scan":
        return (
            "[Допомога: Сканування]\n"
            "1) Швидкий запуск:\n"
            "- скан <ip>\n"
            "- повна перевірка <ip>\n\n"
            "2) Що перевірити у відповіді:\n"
            "- Open ports\n"
            "- New ports vs baseline\n"
            "- Top findings (severity/risk/CVE)\n\n"
            "3) Приклад:\n"
            "- повна перевірка 127.0.0.1"
        )
    if topic == "incidents":
        return (
            "[Допомога: Інциденти]\n"
            "- покажи інциденти\n"
            "- статистика інцидентів\n"
            "- аналіз загроз\n\n"
            "Рекомендація для демо:\n"
            "спочатку запусти повна перевірка <ip>, потім покажи інциденти."
        )
    if topic == "cves":
        return (
            "[Допомога: CVE/База Знань]\n"
            "- покажи критичні cve\n"
            "- пошук cve apache\n"
            "- CVE-2021-44228\n\n"
            "Порада:\n"
            "на захисті покажи зв'язок findings -> CVE -> mitigation."
        )
    if topic == "errors":
        return (
            "[Допомога: Помилки]\n"
            "- покажи помилки\n"
            "- статистика помилок\n\n"
            "Це операційний контур:\n"
            "система дедуплікує помилки та рахує повторення."
        )
    if topic == "demo":
        return (
            "[Допомога: Демо Захисту]\n"
            "Кроки:\n"
            "1. повна перевірка 127.0.0.1\n"
            "2. покажи інциденти\n"
            "3. статистика інцидентів\n"
            "4. пошук cve apache\n"
            "5. статус системи\n"
            "6. план розвитку"
        )

    return (
        "[Меню Користувача]\n"
        "Швидкий старт (для простого користувача):\n"
        "1. повна перевірка 127.0.0.1\n"
        "2. покажи інциденти\n"
        "3. статистика інцидентів\n\n"
        "Основні команди:\n"
        "- допомога\n"
        "- повна перевірка <ip>\n"
        "- скан <ip>\n"
        "- покажи інциденти\n"
        "- статистика інцидентів\n"
        "- покажи критичні cve\n"
        "- пошук cve <ключове_слово>\n"
        "- покажи помилки\n"
        "- статистика помилок\n"
        "- аналіз загроз\n"
        "- статус системи\n"
        "- план розвитку\n\n"
        "Тематична допомога:\n"
        "- допомога сканування\n"
        "- допомога інциденти\n"
        "- допомога cve\n"
        "- допомога помилки\n"
        "- допомога захист\n\n"
        "Приклади:\n"
        "- повна перевірка 127.0.0.1\n"
        "- скан 10.0.0.5\n"
        "- пошук cve apache"
    )


def _format_platform_status(overview: dict, incident_stats: dict, error_stats: dict) -> str:
    return (
        "[Статус Системи]\n"
        f"- CVE records: {overview['total_cves']}\n"
        f"- Assets: {overview['total_assets']}\n"
        f"- Scan runs: {overview['total_scan_runs']}\n"
        f"- Scan findings: {overview['total_scan_findings']}\n"
        f"- Incidents total: {overview['total_incidents']}\n"
        f"- Open incidents: {incident_stats['open_incidents']}\n"
        f"- Critical open incidents: {incident_stats['critical_open_incidents']}\n"
        f"- Error events: {overview['total_errors']}\n"
        f"- Error occurrences: {error_stats['total_occurrences']}\n"
        f"- Last scan at: {overview['last_scan_at'] or 'n/a'}"
    )


def _format_diploma_roadmap() -> str:
    return (
        "[План Розвитку Диплому]\n"
        "Phase 1 (швидко):\n"
        "- Додати 1-2 реальні джерела логів (syslog/Windows Event)\n"
        "- Зробити demo сценарій з 3 атак-ознаками\n\n"
        "Phase 2 (середньо):\n"
        "- NVD auto-import за розкладом\n"
        "- Asset criticality -> risk scoring\n"
        "- SLA-метрики (MTTA/MTTR)\n\n"
        "Phase 3 (enterprise):\n"
        "- Черга задач + воркери для сканів\n"
        "- Multi-tenant RBAC\n"
        "- PDF executive report для керівництва\n\n"
        "KPI для захисту:\n"
        "- >10k CVE у БЗ\n"
        "- Повний цикл: scan -> correlate -> incident -> report\n"
        "- Повторюваний демо-сценарій за 5-7 хв"
    )


def _format_full_check_summary(
    target_ip: str,
    scan_result: dict,
    incident_stats: dict,
    error_stats: dict,
    top_cves,
) -> str:
    lines = [
        "[Full Check]",
        f"- Target: {target_ip}",
        f"- Open ports: {', '.join(str(p) for p in scan_result['open_ports']) if scan_result['open_ports'] else 'none'}",
        f"- New ports vs baseline: {', '.join(str(p) for p in scan_result['new_open_ports']) if scan_result['new_open_ports'] else 'none'}",
        f"- Findings: {len(scan_result['findings'])}",
        "",
        "SOC Snapshot:",
        f"- Total incidents: {incident_stats['total_incidents']}",
        f"- Open incidents: {incident_stats['open_incidents']}",
        f"- Critical open incidents: {incident_stats['critical_open_incidents']}",
        "",
        "Ops Errors Snapshot:",
        f"- Unique errors: {error_stats['total_errors']}",
        f"- Error occurrences: {error_stats['total_occurrences']}",
        "",
        "Top CVEs (CVSS >= 9):",
    ]

    if top_cves:
        for item in top_cves[:5]:
            lines.append(f"- {item.cve_id} | CVSS {item.cvss} | {item.severity}")
    else:
        lines.append("- No records.")
    return "\n".join(lines)


@router.post("/chat")
def process_message(request: ChatRequest, db: Session = Depends(get_db)):
    try:
        message = request.message.strip()
        intent, entities = detect_intent(message)

        if intent == "help_menu":
            return {"type": "text", "message": _format_help_menu(entities.get("topic"))}

        if intent == "platform_status":
            overview = get_platform_overview_stats(db)
            incident_stats = get_incident_summary_stats(db)
            error_stats = get_error_summary_stats(db)
            return {
                "type": "text",
                "message": _format_platform_status(overview, incident_stats, error_stats),
            }

        if intent == "diploma_roadmap":
            return {"type": "text", "message": _format_diploma_roadmap()}

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

        if intent == "search_cves":
            query = entities.get("query")
            cves = search_cves(db, query=query, limit=25)
            if not cves:
                return {"type": "text", "message": "No matching CVEs found."}
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

        if intent == "full_check":
            ip_address = entities.get("ip_address")
            if not ip_address:
                return {"type": "text", "message": "IP address is required: full check <ip>"}
            if not is_valid_ip(ip_address):
                return {"type": "text", "message": "Invalid IP address."}

            scan_result = run_active_scan(db, target=ip_address)
            incident_stats = get_incident_summary_stats(db)
            error_stats = get_error_summary_stats(db)
            top_cves = search_cves(db, min_cvss=9, limit=5)
            return {
                "type": "text",
                "message": _format_full_check_summary(
                    ip_address,
                    scan_result,
                    incident_stats,
                    error_stats,
                    top_cves,
                ),
            }

        if intent == "scan_ip":
            ip_address = entities.get("ip_address")
            if not ip_address:
                return {"type": "text", "message": "IP address is missing."}
            if not is_valid_ip(ip_address):
                return {"type": "text", "message": "Invalid IP address."}

            result = run_active_scan(db, target=ip_address)
            return {"type": "text", "message": _format_active_scan_result(result)}

        if intent == "list_incidents":
            incidents = list_incidents(db, limit=10)
            return {"type": "text", "message": _format_incident_rows(incidents)}

        if intent == "incident_stats":
            stats = get_incident_summary_stats(db)
            return {"type": "text", "message": _format_incident_stats(stats)}

        if intent == "list_errors":
            items = list_error_events(db, limit=10)
            return {"type": "text", "message": _format_error_rows(items)}

        if intent == "error_stats":
            stats = get_error_summary_stats(db)
            return {"type": "text", "message": _format_error_stats(stats)}

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
                    signature=alert_message,
                    actor_role="chat",
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
                    "[Incidents]\n"
                    f"- created: {created_count}\n"
                    f"- updated: {updated_count}\n\n"
                    f"{analysis}\n\n"
                    "[LLM]\n"
                    f"{llm_analysis}"
                ),
            }

        return {
            "type": "text",
            "message": (
                "Невідома команда.\n"
                "Напиши `допомога`, щоб побачити доступні команди."
            ),
        }

    except Exception as exc:
        try:
            tracked = record_exception(
                db,
                source="chat",
                operation="process_message",
                exc=exc,
                severity="MEDIUM",
                context={"message": request.message[:160]},
            )
            reference = str(tracked.id)[:8]
        except Exception:
            reference = "n/a"
        return {
            "type": "text",
            "message": f"Server error. Check backend logs. Error reference: {reference}",
        }
