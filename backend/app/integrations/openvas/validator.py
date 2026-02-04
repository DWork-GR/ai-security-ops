import re

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"


def is_valid_ip(ip: str) -> bool:
    return re.fullmatch(IP_REGEX, ip) is not None
