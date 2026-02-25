import re

SPACE_REGEX = re.compile(r"\s+")
TELEGRAM_TOKEN_REGEX = re.compile(r"\b\d{8,}:[A-Za-z0-9_-]{20,}\b")
BEARER_REGEX = re.compile(r"(?i)\bbearer\s+[a-z0-9._-]+")
ASSIGNMENT_SECRET_REGEX = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|authorization)\b\s*[:=]\s*([^\s;,\"]+)"
)


def sanitize_sensitive_text(value: str | None, *, max_len: int = 600) -> str:
    text = str(value or "")
    if not text:
        return ""

    text = TELEGRAM_TOKEN_REGEX.sub("<redacted_telegram_token>", text)
    text = BEARER_REGEX.sub("Bearer <redacted>", text)
    text = ASSIGNMENT_SECRET_REGEX.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = SPACE_REGEX.sub(" ", text).strip()
    return text[:max_len]
