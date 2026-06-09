import re
from app.nlp.patterns import IP_PATTERN, CVE_PATTERN

FLEXIBLE_CVE_PATTERN = re.compile(
    r"\bCVE[\s:_-]*(\d{4})[\s:_-]+(\d{4,7})\b",
    re.IGNORECASE,
)


def extract_ip(text: str):
    match = re.search(IP_PATTERN, text)
    return match.group(0) if match else None


def extract_cve(text: str):
    match = re.search(CVE_PATTERN, text, re.IGNORECASE)
    if match:
        return match.group(0).upper()

    flexible = FLEXIBLE_CVE_PATTERN.search(text or "")
    if not flexible:
        return None
    return f"CVE-{flexible.group(1)}-{flexible.group(2)}".upper()
