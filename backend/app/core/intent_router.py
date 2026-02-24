from app.nlp.regex_engine import extract_cve, extract_ip


def detect_intent(message: str) -> tuple[str, dict]:
    text = message.lower().strip()
    ip_address = extract_ip(message)
    cve_id = extract_cve(message)

    if cve_id:
        return "cve_lookup", {"cve_id": cve_id.upper()}

    if ip_address and any(
        keyword in text
        for keyword in ["scan", "scan ip", "scan target"]
    ):
        return "scan_ip", {"ip_address": ip_address}

    if "critical" in text and "cve" in text:
        return "critical_cves", {}

    if (
        "show cves" in text
        or "list cves" in text
        or "all cves" in text
    ):
        return "list_cves", {}

    if any(
        keyword in text
        for keyword in [
            "analyze threats",
            "threat analysis",
            "ids analysis",
        ]
    ):
        return "analyze_threats", {}

    return "default", {}
