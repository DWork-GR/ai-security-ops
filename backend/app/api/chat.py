from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.api.rbac import get_current_role
from app.ai.expert_engine import analyze_alerts_expert
from app.ai.gemini_client import analyze_security_incidents
from app.config import CHAT_AUTH_REQUIRED
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
    list_latest_scan_findings,
    list_error_events,
    list_incidents,
    list_scan_runs,
    search_cves,
)
from app.integrations.openvas.validator import ensure_allowed_scan_target
from app.integrations.snort.analyzer import get_critical_alerts
from app.services.error_service import record_exception
from app.services.attack_mapping_service import infer_attack_mapping
from app.services.incident_service import correlate_incident
from app.services.scan_service import run_active_scan

router = APIRouter()


def _ensure_chat_access(x_user_key: str | None) -> str:
    if not CHAT_AUTH_REQUIRED:
        return "chat"

    role = get_current_role(x_user_key)
    if role not in {"analyst", "manager", "admin"}:
        raise HTTPException(status_code=403, detail="Insufficient role")
    return role


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

    lines = [
        "[Incidents] Latest SOC incidents:",
        "",
        "| detected_at | severity | status | source | ATT&CK | message |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for incident in incidents:
        message = (incident.message or "").replace("|", "/").replace("\n", " ").strip()
        attack = infer_attack_mapping(source=incident.source, message=incident.message)
        attack_tag = attack["attack_technique_id"] or "n/a"
        lines.append(
            f"| {incident.detected_at.isoformat()} | {incident.severity} | "
            f"{incident.status} | {incident.source} | {attack_tag} | {message} |"
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
    lines = [
        "[Errors] Latest error events:",
        "",
        "| last_seen_at | severity | operation | error_type | count |",
        "| --- | --- | --- | --- | --- |",
    ]
    for item in items:
        operation = f"{item.source}.{item.operation}".replace("|", "/")
        error_type = (item.error_type or "").replace("|", "/")
        lines.append(
            f"| {item.last_seen_at.isoformat()} | {item.severity} | {operation} | "
            f"{error_type} | {item.occurrences} |"
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


def _build_soc_evidence(db: Session) -> list[str]:
    evidence: list[str] = []

    stats = get_incident_summary_stats(db)
    evidence.append(
        "SOC_STATS "
        f"total_incidents={stats['total_incidents']} "
        f"open_incidents={stats['open_incidents']} "
        f"critical_open_incidents={stats['critical_open_incidents']} "
        f"by_source={stats['by_source']} "
        f"by_severity={stats['by_severity']}"
    )

    for incident in list_incidents(db, limit=10):
        attack = infer_attack_mapping(source=incident.source, message=incident.message)
        evidence.append(
            "INCIDENT "
            f"id={incident.id} source={incident.source} severity={incident.severity} "
            f"status={incident.status} asset={getattr(incident, 'asset', None) or 'n/a'} "
            f"attack={attack['attack_technique_id'] or 'n/a'} "
            f"message={incident.message}"
        )

    for scan_run in list_scan_runs(db, limit=5):
        evidence.append(
            "SCAN_RUN "
            f"task_id={scan_run.task_id} target={scan_run.target_ip} "
            f"profile={scan_run.scan_profile} status={scan_run.status} "
            f"scanned_ports={scan_run.scanned_ports} open_ports={scan_run.open_ports_count} "
            f"duration_ms={scan_run.duration_ms} finished_at={scan_run.finished_at.isoformat()}"
        )

    for finding, scan_run in list_latest_scan_findings(db, limit=20):
        evidence.append(
            "SCAN_FINDING "
            f"source_profile={scan_run.scan_profile} target={scan_run.target_ip} "
            f"port={finding.port}/{finding.protocol} service={finding.service} "
            f"severity={finding.severity} risk={finding.risk_score} cvss={finding.cvss_max} "
            f"cves={finding.cve_refs or 'n/a'} summary={finding.summary_en}"
        )

    for alert in get_critical_alerts()[:10]:
        evidence.append(
            "SNORT_ALERT "
            f"priority={alert['priority']} src={alert.get('src_ip') or 'n/a'} "
            f"dst={alert.get('dst_ip') or 'n/a'} message={alert['message']}"
        )

    for error_item in list_error_events(db, limit=5):
        evidence.append(
            "INTEGRATION_ERROR "
            f"source={error_item.source} operation={error_item.operation} "
            f"severity={error_item.severity} occurrences={error_item.occurrences} "
            f"message={error_item.message}"
        )

    return evidence


def _format_rule_based_soc_assessment(evidence: list[str]) -> str:
    if not evidence:
        return (
            "[EN] Rule-Based SOC Assessment\n"
            "Executive Summary:\n"
            "- No scanner, incident, or IDS evidence is available yet.\n"
            "Next Actions:\n"
            "- Run Nmap/OpenVAS scans or forward Snort alerts, then repeat analysis.\n\n"
            "[UK] Rule-Based SOC Оцінка\n"
            "Короткий Висновок:\n"
            "- Даних від сканерів, інцидентів або IDS ще немає.\n"
            "Наступні Дії:\n"
            "- Запустіть Nmap/OpenVAS або передайте Snort alerts, потім повторіть аналіз."
        )

    scan_findings = [item for item in evidence if item.startswith("SCAN_FINDING")]
    snort_alerts = [item for item in evidence if item.startswith("SNORT_ALERT")]
    incidents = [item for item in evidence if item.startswith("INCIDENT")]
    errors = [item for item in evidence if item.startswith("INTEGRATION_ERROR")]
    critical_or_high = [
        item for item in scan_findings + incidents + snort_alerts
        if "severity=CRITICAL" in item or "severity=HIGH" in item or "priority=1" in item
    ]

    lines = [
        "[EN] Rule-Based SOC Assessment",
        "Executive Summary:",
        f"- Evidence items reviewed: {len(evidence)}.",
        f"- Scanner findings: {len(scan_findings)}, IDS critical alerts: {len(snort_alerts)}, incidents: {len(incidents)}.",
        f"- High-priority signals: {len(critical_or_high)}.",
        "",
        "What This Means:",
    ]
    if scan_findings:
        lines.append("- Exposed services from Nmap/OpenVAS are present and should be validated against asset purpose.")
    if snort_alerts:
        lines.append("- Snort has produced priority-1 alerts, so traffic evidence should be correlated with exposed services.")
    if incidents:
        lines.append("- Incidents already exist in the SOC queue; prioritize open HIGH/CRITICAL items first.")
    if errors:
        lines.append("- Integration errors exist; verify scanner/IDS reliability before relying on absence of alerts.")
    if not any([scan_findings, snort_alerts, incidents]):
        lines.append("- There is not enough operational evidence yet for a confident threat assessment.")

    lines.extend(["", "Recommended Analyst Actions:"])
    lines.append("- Confirm whether each exposed port is expected for the asset owner and environment.")
    lines.append("- For HIGH/CRITICAL findings, collect service banners, patch state, and recent authentication logs.")
    lines.append("- Correlate Snort source/destination IPs with scan targets and incident timestamps.")
    lines.append("- Close or firewall unused services, then rescan to validate the fix.")

    lines.extend([
        "",
        "[UK] Rule-Based SOC Оцінка",
        "Короткий Висновок:",
        f"- Переглянуто доказів: {len(evidence)}.",
        f"- Знахідки сканерів: {len(scan_findings)}, критичні IDS alerts: {len(snort_alerts)}, інциденти: {len(incidents)}.",
        "Дії Аналітика:",
        "- Перевірити, чи кожен відкритий порт очікуваний для цього активу.",
        "- Для HIGH/CRITICAL зібрати банери сервісів, стан патчів і логи автентифікації.",
        "- Зіставити Snort IP з цілями сканування та часом інцидентів.",
        "- Закрити або обмежити непотрібні сервіси і повторити сканування.",
    ])

    return "\n".join(lines)


@router.post("/chat")
def process_message(
    request: ChatRequest,
    db: Session = Depends(get_db),
    x_user_key: str | None = Header(default=None, alias="X-User-Key"),
):
    chat_actor_role = _ensure_chat_access(x_user_key)
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
            try:
                ip_address = ensure_allowed_scan_target(ip_address)
            except ValueError as exc:
                return {"type": "text", "message": str(exc)}

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
            try:
                ip_address = ensure_allowed_scan_target(ip_address)
            except ValueError as exc:
                return {"type": "text", "message": str(exc)}

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
                    actor_role=chat_actor_role,
                )
                if created:
                    created_count += 1
                else:
                    updated_count += 1

            evidence = _build_soc_evidence(db)
            if not evidence:
                evidence = ["NO_EVIDENCE No scanner findings, incidents, Snort alerts, or integration errors were found."]

            snort_analysis = analyze_alerts_expert(alert_messages)
            rule_analysis = _format_rule_based_soc_assessment(evidence)
            llm_analysis = analyze_security_incidents(evidence)
            return {
                "type": "text",
                "message": (
                    "[Incidents]\n"
                    f"- created: {created_count}\n"
                    f"- updated: {updated_count}\n\n"
                    "[Evidence]\n"
                    f"- items: {len(evidence)}\n"
                    f"- snort_priority_1_alerts: {len(alert_messages)}\n\n"
                    f"{rule_analysis}\n\n"
                    "[Snort Rule Engine]\n"
                    f"{snort_analysis}\n\n"
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
