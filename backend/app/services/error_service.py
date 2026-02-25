import hashlib
import re
from typing import Any

from sqlalchemy.orm import Session

from app.database.repository import create_or_increment_error_event
from app.utils.sanitization import sanitize_sensitive_text

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HEX_REGEX = re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE)
NUMBER_REGEX = re.compile(r"\b\d+\b")
SPACE_REGEX = re.compile(r"\s+")


def _normalize_message(message: str) -> str:
    normalized = (message or "").lower()
    normalized = IP_REGEX.sub("<ip>", normalized)
    normalized = HEX_REGEX.sub("<hex>", normalized)
    normalized = NUMBER_REGEX.sub("<n>", normalized)
    normalized = SPACE_REGEX.sub(" ", normalized).strip()
    return normalized[:600]


def build_error_fingerprint(
    *,
    source: str,
    operation: str,
    error_type: str,
    message: str,
) -> str:
    payload = "||".join(
        [
            (source or "unknown").lower().strip() or "unknown",
            (operation or "unknown").lower().strip() or "unknown",
            (error_type or "Exception").lower().strip() or "exception",
            _normalize_message(message),
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _format_context(context: dict[str, Any] | None) -> str | None:
    if not context:
        return None
    chunks: list[str] = []
    for key, value in context.items():
        sanitized = sanitize_sensitive_text(str(value), max_len=160)
        chunks.append(f"{key}={sanitized}")
    return ";".join(chunks)[:1000]


def record_exception(
    db: Session,
    *,
    source: str,
    operation: str,
    exc: Exception,
    severity: str = "MEDIUM",
    context: dict[str, Any] | None = None,
):
    error_type = exc.__class__.__name__
    message = sanitize_sensitive_text(str(exc) or error_type, max_len=1000) or error_type
    fingerprint = build_error_fingerprint(
        source=source,
        operation=operation,
        error_type=error_type,
        message=message,
    )
    return create_or_increment_error_event(
        db,
        source=source,
        operation=operation,
        error_type=error_type,
        message=message,
        severity=severity,
        fingerprint=fingerprint,
        context=_format_context(context),
    )
