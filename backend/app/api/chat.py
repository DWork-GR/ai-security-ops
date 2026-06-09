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


def _normalize_language(language: str | None) -> str:
    value = (language or "en").strip().lower()
    return value if value in {"uk", "en", "duo"} else "uk"


def _detect_message_language(message: str) -> str:
    return "uk" if any("а" <= char.lower() <= "я" or char in "іїєґІЇЄҐ" for char in message or "") else "en"


def _pick(language: str, *, en: str, uk: str) -> str:
    if language == "en":
        return en
    if language == "duo":
        return f"{uk}\n\n[EN]\n{en}"
    return uk


def _select_marked_language(text: str, language: str) -> str:
    if language == "duo":
        return text
    marker = "[UK]" if language == "uk" else "[EN]"
    other = "[EN]" if language == "uk" else "[UK]"
    start = text.find(marker)
    if start == -1:
        return text
    start += len(marker)
    end = text.find(other, start)
    if end == -1:
        return text[start:].strip()
    return text[start:end].strip()


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


def _format_incident_rows(incidents, language: str = "uk") -> str:
    if not incidents:
        return _pick(language, en="No incidents found.", uk="Інцидентів не знайдено.")

    lines = _pick(
        language,
        en=(
            "[Incidents] Latest SOC incidents:\n\n"
            "| detected_at | severity | status | source | ATT&CK | message |\n"
            "| --- | --- | --- | --- | --- | --- |"
        ),
        uk=(
            "[Інциденти] Останні SOC-інциденти:\n\n"
            "| час | критичність | статус | джерело | ATT&CK | повідомлення |\n"
            "| --- | --- | --- | --- | --- | --- |"
        ),
    ).splitlines()
    for incident in incidents:
        message = (incident.message or "").replace("|", "/").replace("\n", " ").strip()
        attack = infer_attack_mapping(source=incident.source, message=incident.message)
        attack_tag = attack["attack_technique_id"] or "n/a"
        lines.append(
            f"| {incident.detected_at.isoformat()} | {incident.severity} | "
            f"{incident.status} | {incident.source} | {attack_tag} | {message} |"
        )
    return "\n".join(lines)


def _format_incident_stats(stats: dict, language: str = "uk") -> str:
    if language == "en":
        title = "[SOC KPI Snapshot]"
        labels = {
            "total": "Total incidents",
            "open": "Open incidents",
            "critical": "Critical open incidents",
            "last24": "Incidents in last 24h",
            "severity": "By severity:",
            "source": "By source:",
            "status": "By status:",
        }
    else:
        title = "[SOC KPI Знімок]"
        labels = {
            "total": "Усього інцидентів",
            "open": "Відкриті інциденти",
            "critical": "Критичні відкриті інциденти",
            "last24": "Інциденти за останні 24 год",
            "severity": "За критичністю:",
            "source": "За джерелом:",
            "status": "За статусом:",
        }
    lines = [
        title,
        f"- {labels['total']}: {stats['total_incidents']}",
        f"- {labels['open']}: {stats['open_incidents']}",
        f"- {labels['critical']}: {stats['critical_open_incidents']}",
        f"- {labels['last24']}: {stats['incidents_last_24h']}",
        "",
        labels["severity"],
    ]
    for severity, count in sorted(stats["by_severity"].items()):
        lines.append(f"- {severity}: {count}")

    lines.append("")
    lines.append(labels["source"])
    for source, count in sorted(stats["by_source"].items()):
        lines.append(f"- {source}: {count}")

    lines.append("")
    lines.append(labels["status"])
    for status, count in sorted(stats["by_status"].items()):
        lines.append(f"- {status}: {count}")

    return "\n".join(lines)


def _format_active_scan_result(result: dict, language: str = "uk") -> str:
    none_text = "none" if language == "en" else "немає"
    lines = [
        "[Active Scan]" if language == "en" else "[Активне Сканування]",
        f"- {'Task ID' if language == 'en' else 'ID завдання'}: {result['task_id']}",
        f"- {'Target' if language == 'en' else 'Ціль'}: {result['target']}",
        f"- {'Status' if language == 'en' else 'Статус'}: {result['status']}",
        f"- {'Scan profile' if language == 'en' else 'Профіль сканування'}: {result['scan_profile']}",
        f"- {'Scanned ports' if language == 'en' else 'Перевірено портів'}: {result['scanned_ports']}",
        f"- {'Open ports' if language == 'en' else 'Відкриті порти'}: {', '.join(str(p) for p in result['open_ports']) if result['open_ports'] else none_text}",
        f"- {'New open ports vs baseline' if language == 'en' else 'Нові відкриті порти проти baseline'}: {', '.join(str(p) for p in result['new_open_ports']) if result['new_open_ports'] else none_text}",
        f"- {'Closed open ports vs baseline' if language == 'en' else 'Закриті порти проти baseline'}: {', '.join(str(p) for p in result['closed_open_ports']) if result['closed_open_ports'] else none_text}",
        f"- {'Findings' if language == 'en' else 'Знахідок'}: {len(result['findings'])}",
        f"- {'Incidents' if language == 'en' else 'Інциденти'}: created={result['incidents_created']}, updated={result['incidents_updated']}",
    ]

    if result["findings"]:
        lines.append("")
        lines.append("Top findings:" if language == "en" else "Топ знахідок:")
        for finding in result["findings"][:5]:
            cves = ", ".join(finding["cve_references"]) if finding["cve_references"] else "n/a"
            lines.append(
                f"- {finding['severity']} | {finding['service']}:{finding['port']} | "
                f"risk={finding['risk_score']} | CVEs={cves}"
            )
    return "\n".join(lines)


def _format_error_rows(items, language: str = "uk") -> str:
    if not items:
        return _pick(language, en="No error events found.", uk="Подій помилок не знайдено.")
    lines = _pick(
        language,
        en="[Errors] Latest error events:\n\n| last_seen_at | severity | operation | error_type | count |\n| --- | --- | --- | --- | --- |",
        uk="[Помилки] Останні події помилок:\n\n| останній_раз | критичність | операція | тип_помилки | кількість |\n| --- | --- | --- | --- | --- |",
    ).splitlines()
    for item in items:
        operation = f"{item.source}.{item.operation}".replace("|", "/")
        error_type = (item.error_type or "").replace("|", "/")
        lines.append(
            f"| {item.last_seen_at.isoformat()} | {item.severity} | {operation} | "
            f"{error_type} | {item.occurrences} |"
        )
    return "\n".join(lines)


def _format_error_stats(stats: dict, language: str = "uk") -> str:
    if language == "en":
        labels = {
            "title": "[Error Stats]",
            "total": "Total unique errors",
            "occurrences": "Total occurrences",
            "last24": "Errors in last 24h",
            "severity": "By severity:",
            "source": "By source:",
        }
    else:
        labels = {
            "title": "[Статистика Помилок]",
            "total": "Унікальних помилок",
            "occurrences": "Усього повторень",
            "last24": "Помилки за останні 24 год",
            "severity": "За критичністю:",
            "source": "За джерелом:",
        }
    lines = [
        labels["title"],
        f"- {labels['total']}: {stats['total_errors']}",
        f"- {labels['occurrences']}: {stats['total_occurrences']}",
        f"- {labels['last24']}: {stats['errors_last_24h']}",
        "",
        labels["severity"],
    ]
    for key, value in sorted(stats["by_severity"].items()):
        lines.append(f"- {key}: {value}")
    lines.append("")
    lines.append(labels["source"])
    for key, value in sorted(stats["by_source"].items()):
        lines.append(f"- {key}: {value}")
    return "\n".join(lines)


def _format_help_menu(topic: str | None = None, language: str = "uk") -> str:
    if language == "en":
        if topic == "scan":
            return (
                "[Help: Scanning]\n"
                "Quick commands:\n"
                "- scan <ip>\n"
                "- full check <ip>\n\n"
                "The response shows open ports, baseline changes, findings, and created/updated incidents.\n\n"
                "Example:\n"
                "- full check 127.0.0.1"
            )
        if topic == "incidents":
            return (
                "[Help: Incidents]\n"
                "- show incidents\n"
                "- incident stats\n"
                "- analyze threats\n\n"
                "Recommended demo flow: run full check <ip>, then show incidents."
            )
        if topic == "cves":
            return (
                "[Help: CVE Knowledge Base]\n"
                "- show critical cves\n"
                "- search cve apache\n"
                "- CVE-2021-44228"
            )
        if topic == "errors":
            return (
                "[Help: Errors]\n"
                "- show errors\n"
                "- error stats\n\n"
                "This view tracks integration and operational failures."
            )
        return (
            "[User Menu]\n"
            "Quick start:\n"
            "1. full check 127.0.0.1\n"
            "2. show incidents\n"
            "3. incident stats\n\n"
            "Main commands:\n"
            "- help\n"
            "- full check <ip>\n"
            "- scan <ip>\n"
            "- show incidents\n"
            "- incident stats\n"
            "- show critical cves\n"
            "- search cve <keyword>\n"
            "- show errors\n"
            "- error stats\n"
            "- analyze threats\n"
            "- system status\n"
            "- roadmap"
        )
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


def _format_platform_status(overview: dict, incident_stats: dict, error_stats: dict, language: str = "uk") -> str:
    if language == "en":
        return (
            "[System Status]\n"
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
    return (
        "[Статус Системи]\n"
        f"- CVE-записів: {overview['total_cves']}\n"
        f"- Активів: {overview['total_assets']}\n"
        f"- Запусків сканування: {overview['total_scan_runs']}\n"
        f"- Знахідок сканування: {overview['total_scan_findings']}\n"
        f"- Усього інцидентів: {overview['total_incidents']}\n"
        f"- Відкриті інциденти: {incident_stats['open_incidents']}\n"
        f"- Критичні відкриті інциденти: {incident_stats['critical_open_incidents']}\n"
        f"- Подій помилок: {overview['total_errors']}\n"
        f"- Повторень помилок: {error_stats['total_occurrences']}\n"
        f"- Останній скан: {overview['last_scan_at'] or 'n/a'}"
    )


def _format_diploma_roadmap(language: str = "uk") -> str:
    if language == "en":
        return (
            "[Diploma Development Roadmap]\n"
            "Phase 1 (quick):\n"
            "- Add 1-2 real log sources (syslog/Windows Event)\n"
            "- Build a repeatable demo scenario with 3 attack signals\n\n"
            "Phase 2 (medium):\n"
            "- Scheduled NVD auto-import\n"
            "- Asset criticality -> risk scoring\n"
            "- SLA metrics (MTTA/MTTR)\n\n"
            "Phase 3 (enterprise):\n"
            "- Scan queue plus workers\n"
            "- Multi-tenant RBAC\n"
            "- PDF executive report for management\n\n"
            "Defense KPI:\n"
            "- >10k CVEs in the knowledge base\n"
            "- Full cycle: scan -> correlate -> incident -> report\n"
            "- Repeatable 5-7 minute demo scenario"
        )
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
    language: str = "uk",
) -> str:
    if language == "uk":
        lines = [
            "[Повна Перевірка]",
            f"- Ціль: {target_ip}",
            f"- Відкриті порти: {', '.join(str(p) for p in scan_result['open_ports']) if scan_result['open_ports'] else 'немає'}",
            f"- Нові порти проти baseline: {', '.join(str(p) for p in scan_result['new_open_ports']) if scan_result['new_open_ports'] else 'немає'}",
            f"- Знахідок: {len(scan_result['findings'])}",
            "",
            "SOC Знімок:",
            f"- Усього інцидентів: {incident_stats['total_incidents']}",
            f"- Відкриті інциденти: {incident_stats['open_incidents']}",
            f"- Критичні відкриті інциденти: {incident_stats['critical_open_incidents']}",
            "",
            "Знімок Операційних Помилок:",
            f"- Унікальних помилок: {error_stats['total_errors']}",
            f"- Повторень помилок: {error_stats['total_occurrences']}",
            "",
            "Топ CVE (CVSS >= 9):",
        ]
        if top_cves:
            for item in top_cves[:5]:
                lines.append(f"- {item.cve_id} | CVSS {item.cvss} | {item.severity}")
        else:
            lines.append("- Записів немає.")
        return "\n".join(lines)

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


def _format_rule_based_soc_assessment(evidence: list[str], language: str = "uk") -> str:
    if not evidence:
        return _select_marked_language(
            "[EN] Rule-Based SOC Assessment\n"
            "Executive Summary:\n"
            "- No scanner, incident, or IDS evidence is available yet.\n"
            "Next Actions:\n"
            "- Run Nmap/OpenVAS scans or forward Snort alerts, then repeat analysis.\n\n"
            "[UK] Rule-Based SOC Оцінка\n"
            "Короткий Висновок:\n"
            "- Даних від сканерів, інцидентів або IDS ще немає.\n"
            "Наступні Дії:\n"
            "- Запустіть Nmap/OpenVAS або передайте Snort alerts, потім повторіть аналіз.",
            language,
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

    return _select_marked_language("\n".join(lines), language)


@router.post("/chat")
def process_message(
    request: ChatRequest,
    db: Session = Depends(get_db),
    x_user_key: str | None = Header(default=None, alias="X-User-Key"),
):
    chat_actor_role = _ensure_chat_access(x_user_key)
    try:
        message = request.message.strip()
        language = _normalize_language(request.language) if request.language else _detect_message_language(message)
        intent, entities = detect_intent(message)

        if intent == "help_menu":
            return {"type": "text", "message": _format_help_menu(entities.get("topic"), language)}

        if intent == "platform_status":
            overview = get_platform_overview_stats(db)
            incident_stats = get_incident_summary_stats(db)
            error_stats = get_error_summary_stats(db)
            return {
                "type": "text",
                "message": _format_platform_status(overview, incident_stats, error_stats, language),
            }

        if intent == "diploma_roadmap":
            return {"type": "text", "message": _format_diploma_roadmap(language)}

        if intent == "list_cves":
            cves = get_all_cves(db) or []
            if not cves:
                return {"type": "text", "message": _pick(language, en="No CVE records found.", uk="CVE-записи відсутні.")}
            return {"type": "cves", "cves": _serialize_cves(cves)}

        if intent == "critical_cves":
            cves = get_critical_cves(db) or []
            if not cves:
                return {"type": "text", "message": _pick(language, en="No critical CVEs found.", uk="Критичних CVE не знайдено.")}
            return {"type": "cves", "cves": _serialize_cves(cves)}

        if intent == "search_cves":
            query = entities.get("query")
            cves = search_cves(db, query=query, limit=25)
            if not cves:
                return {"type": "text", "message": _pick(language, en="No matching CVEs found.", uk="Відповідних CVE не знайдено.")}
            return {"type": "cves", "cves": _serialize_cves(cves)}

        if intent == "cve_lookup":
            cve_id = entities.get("cve_id")
            if not cve_id:
                return {"type": "text", "message": _pick(language, en="CVE identifier is missing.", uk="Ідентифікатор CVE відсутній.")}

            cve = get_cve_by_id(db, cve_id)
            if not cve:
                return {"type": "text", "message": _pick(language, en=f"CVE {cve_id} was not found.", uk=f"CVE {cve_id} не знайдено.")}

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
                return {"type": "text", "message": _pick(language, en="IP address is required: full check <ip>", uk="Потрібна IP-адреса: повна перевірка <ip>")}
            try:
                ip_address = ensure_allowed_scan_target(ip_address)
            except ValueError as exc:
                return {"type": "text", "message": str(exc)}

            scan_result = run_active_scan(db, target=ip_address, source="nmap")
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
                    language,
                ),
            }

        if intent == "scan_ip":
            ip_address = entities.get("ip_address")
            if not ip_address:
                return {"type": "text", "message": _pick(language, en="IP address is missing.", uk="IP-адресу не вказано.")}
            try:
                ip_address = ensure_allowed_scan_target(ip_address)
            except ValueError as exc:
                return {"type": "text", "message": str(exc)}

            result = run_active_scan(db, target=ip_address, source="nmap")
            return {"type": "text", "message": _format_active_scan_result(result, language)}

        if intent == "list_incidents":
            incidents = list_incidents(db, limit=10)
            return {"type": "text", "message": _format_incident_rows(incidents, language)}

        if intent == "incident_stats":
            stats = get_incident_summary_stats(db)
            return {"type": "text", "message": _format_incident_stats(stats, language)}

        if intent == "list_errors":
            items = list_error_events(db, limit=10)
            return {"type": "text", "message": _format_error_rows(items, language)}

        if intent == "error_stats":
            stats = get_error_summary_stats(db)
            return {"type": "text", "message": _format_error_stats(stats, language)}

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
            rule_analysis = _format_rule_based_soc_assessment(evidence, language)
            llm_analysis = analyze_security_incidents(evidence, language=language)
            summary_block = (
                "[Incidents]\n"
                f"- created: {created_count}\n"
                f"- updated: {updated_count}\n\n"
                "[Evidence]\n"
                f"- items: {len(evidence)}\n"
                f"- snort_priority_1_alerts: {len(alert_messages)}\n\n"
                if language == "en"
                else
                "[Інциденти]\n"
                f"- створено: {created_count}\n"
                f"- оновлено: {updated_count}\n\n"
                "[Докази]\n"
                f"- елементів: {len(evidence)}\n"
                f"- snort_priority_1_alerts: {len(alert_messages)}\n\n"
            )
            return {
                "type": "text",
                "message": (
                    summary_block +
                    f"{rule_analysis}\n\n"
                    f"[{'Snort Rule Engine' if language == 'en' else 'Snort Rule Engine'}]\n"
                    f"{snort_analysis}\n\n"
                    "[LLM]\n"
                    f"{llm_analysis}"
                ),
            }

        return {
            "type": "text",
            "message": _pick(
                language,
                en="Unknown command.\nType `help` to see available commands.",
                uk="Невідома команда.\nНапиши `допомога`, щоб побачити доступні команди.",
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
            "message": _pick(
                _normalize_language(getattr(request, "language", "uk")),
                en=f"Server error. Check backend logs. Error reference: {reference}",
                uk=f"Помилка сервера. Перевір логи бекенду. Код помилки: {reference}",
            ),
        }
