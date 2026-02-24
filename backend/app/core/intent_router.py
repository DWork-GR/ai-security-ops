import re

from app.nlp.regex_engine import extract_cve, extract_ip

SPACE_REGEX = re.compile(r"\s+")
PUNCT_REGEX = re.compile(r"[!?;,\(\)\[\]{}\"']")


def _normalize_text(message: str) -> str:
    text = (message or "").lower().strip()
    text = text.replace("ё", "е")
    text = text.replace("’", "'")
    text = PUNCT_REGEX.sub(" ", text)
    text = SPACE_REGEX.sub(" ", text).strip()
    return text


def _has_any(text: str, phrases: list[str]) -> bool:
    return any(phrase in text for phrase in phrases)


def _extract_help_topic(text: str) -> str | None:
    topic_map = {
        "scan": [
            "scan",
            "скан",
            "сканування",
            "перевірка ip",
        ],
        "incidents": [
            "incident",
            "інцидент",
            "инцидент",
        ],
        "cves": [
            "cve",
            "вразлив",
            "уязв",
        ],
        "errors": [
            "error",
            "помил",
            "ошиб",
        ],
        "demo": [
            "demo",
            "демо",
            "захист",
            "defense",
        ],
    }
    for topic, markers in topic_map.items():
        if any(marker in text for marker in markers):
            return topic
    return None


def detect_intent(message: str) -> tuple[str, dict]:
    text = _normalize_text(message)
    ip_address = extract_ip(message)
    cve_id = extract_cve(message)

    if _has_any(
        text,
        [
            "help",
            "menu",
            "commands",
            "what can you do",
            "show commands",
            "допомога",
            "допоможи",
            "команди",
            "що ти вмієш",
        ],
    ):
        return "help_menu", {"topic": _extract_help_topic(text)}

    if _has_any(
        text,
        [
            "system status",
            "platform status",
            "diploma status",
            "статус системи",
            "статус платформи",
            "статус диплома",
            "звіт системи",
        ],
    ):
        return "platform_status", {}

    if _has_any(
        text,
        [
            "roadmap",
            "improve diploma",
            "strengthen diploma",
            "план розвитку",
            "як посилити диплом",
            "усилить диплом",
            "как усилить диплом",
        ],
    ):
        return "diploma_roadmap", {}

    if _has_any(
        text,
        [
            "full check",
            "quick check",
            "runbook",
            "повна перевірка",
            "швидка перевірка",
        ],
    ):
        return "full_check", {"ip_address": ip_address}

    if cve_id:
        return "cve_lookup", {"cve_id": cve_id.upper()}

    if ip_address and _has_any(
        text,
        [
            "scan",
            "scan ip",
            "scan target",
            "скан",
            "скануй",
            "сканувати",
            "перевір ip",
            "перевір ip адресу",
        ],
    ):
        return "scan_ip", {"ip_address": ip_address}

    if ("critical" in text and "cve" in text) or ("критич" in text and "cve" in text):
        return "critical_cves", {}

    if _has_any(
        text,
        [
            "show cves",
            "list cves",
            "all cves",
            "покажи cve",
            "список cve",
            "усі cve",
            "всі cve",
        ],
    ):
        return "list_cves", {}

    search_match = re.match(r"^(search|find|пошук|знайди)\s+cve\s+(.+)$", text)
    if search_match:
        return "search_cves", {"query": search_match.group(2).strip()}

    if _has_any(
        text,
        [
            "analyze threats",
            "threat analysis",
            "ids analysis",
            "аналіз загроз",
            "проаналізуй загрози",
        ],
    ):
        return "analyze_threats", {}

    if _has_any(
        text,
        [
            "incident stats",
            "incidents summary",
            "soc stats",
            "статистика інцидентів",
            "зведення інцидентів",
            "soc статистика",
        ],
    ):
        return "incident_stats", {}

    if _has_any(
        text,
        [
            "show incidents",
            "list incidents",
            "open incidents",
            "покажи інциденти",
            "список інцидентів",
            "відкриті інциденти",
        ],
    ):
        return "list_incidents", {}

    if _has_any(
        text,
        [
            "show errors",
            "list errors",
            "error log",
            "покажи помилки",
            "список помилок",
            "журнал помилок",
        ],
    ):
        return "list_errors", {}

    if _has_any(
        text,
        [
            "error stats",
            "errors summary",
            "error summary",
            "статистика помилок",
            "зведення помилок",
        ],
    ):
        return "error_stats", {}

    return "default", {}
