import re
from app.nlp.patterns import IP_PATTERN, CVE_PATTERN


def extract_ip(text: str):
    match = re.search(IP_PATTERN, text)
    return match.group(0) if match else None


def extract_cve(text: str):
    match = re.search(CVE_PATTERN, text, re.IGNORECASE)
    return match.group(0) if match else None
