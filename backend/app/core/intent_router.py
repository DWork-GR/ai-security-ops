from app.nlp.regex_engine import extract_ip, extract_cve


def detect_intent(message: str) -> tuple[str, dict]:
    text = message.lower()

    ip = extract_ip(message)
    cve = extract_cve(message)

    # 🔹 Список усіх уразливостей
    if (
        ("покажи" in text or "показати" in text)
        and ("уразлив" in text or "cve" in text)
    ):
        return "list_cves", {}

    # 🔹 Критичні уразливості
    if (
        "критич" in text
        and ("уразлив" in text or "cve" in text)
    ):
        return "critical_cves", {}

    # 🔹 Конкретна CVE
    if cve:
        return "cve_lookup", {"cve_id": cve}

    # 🔹 IP → scan
    if ip:
        return "scan_ip", {"ip_address": ip}

    # 🔹 Аналіз загроз
    if any(word in text for word in ["threat", "загрози", "attack"]):
        return "analyze_threats", {}

    return "default", {}
