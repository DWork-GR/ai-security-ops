from app.nlp.regex_engine import extract_ip, extract_cve


def detect_intent(message: str) -> tuple[str, dict]:
    message_lower = message.lower()

    ip = extract_ip(message)
    cve = extract_cve(message)

    if ip:
        return "scan_ip", {"ip_address": ip}

    if cve:
        return "cve_lookup", {"cve_id": cve}

    if any(word in message_lower for word in ["threat", "загрози", "attack"]):
        return "analyze_threats", {}

    return "default", {}
