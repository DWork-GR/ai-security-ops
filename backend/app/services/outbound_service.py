import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app import config
from app.database.repository import (
    create_outbound_event,
    get_outbound_event_by_fingerprint,
    mark_outbound_attempt_failed,
    mark_outbound_attempt_sent,
)
from app.services.error_service import record_exception

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def _normalize_severity(value: str) -> str:
    normalized = (value or "").upper().strip()
    if normalized in SEVERITY_RANK:
        return normalized
    return "MEDIUM"


def _can_notify_for_severity(severity: str) -> bool:
    current_rank = SEVERITY_RANK.get(_normalize_severity(severity), 2)
    min_rank = SEVERITY_RANK.get(_normalize_severity(config.OUTBOUND_MIN_SEVERITY), 3)
    return current_rank >= min_rank


def _configured_channels() -> list[str]:
    channels: list[str] = []
    if config.OUTBOUND_WEBHOOK_URL:
        channels.append("webhook")
    if config.TELEGRAM_BOT_TOKEN and config.TELEGRAM_CHAT_ID:
        channels.append("telegram")
    if config.GITHUB_TOKEN and config.GITHUB_REPO:
        channels.append("github")
    return channels


def _fingerprint_for_delivery(*, channel: str, event_key: str) -> str:
    payload = f"{channel}|{event_key}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _infer_asset(message: str) -> str | None:
    match = IP_REGEX.search(message or "")
    if not match:
        return None
    return match.group(0)


def _request_json(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
):
    timeout_sec = max(1.0, float(config.OUTBOUND_TIMEOUT_MS) / 1000.0)
    with httpx.Client(timeout=timeout_sec) as client:
        response = client.request(
            method=method.upper(),
            url=url,
            headers=headers,
            json=payload,
        )
    if response.status_code < 200 or response.status_code >= 300:
        body = (response.text or "").strip().replace("\n", " ")
        raise RuntimeError(
            f"Outbound HTTP {response.status_code} for {url}: {body[:300]}"
        )
    return response


def _send_webhook(*, payload: dict[str, Any], idempotency_key: str):
    headers = {
        "Content-Type": "application/json",
        "Idempotency-Key": idempotency_key,
    }
    if config.OUTBOUND_WEBHOOK_TOKEN:
        headers["Authorization"] = f"Bearer {config.OUTBOUND_WEBHOOK_TOKEN}"
    _request_json(
        method="POST",
        url=config.OUTBOUND_WEBHOOK_URL,
        headers=headers,
        payload=payload,
    )


def _send_telegram(*, payload: dict[str, Any], idempotency_key: str):
    url = f"https://api.telegram.org/bot{config.TELEGRAM_BOT_TOKEN}/sendMessage"
    incident = payload["incident"]
    message = (
        f"[{incident['severity']}] Incident {incident['id']}\n"
        f"Source: {incident['source']}\n"
        f"Status: {incident['status']}\n"
        f"Asset: {incident['asset'] or 'n/a'}\n"
        f"Message: {incident['message'][:500]}\n"
        f"Event: {payload['event_type']} ({payload['event_key']})"
    )
    _request_json(
        method="POST",
        url=url,
        headers={"Idempotency-Key": idempotency_key},
        payload={
            "chat_id": config.TELEGRAM_CHAT_ID,
            "text": message,
            "disable_web_page_preview": True,
        },
    )


def _send_github_issue(*, payload: dict[str, Any], idempotency_key: str):
    url = f"https://api.github.com/repos/{config.GITHUB_REPO}/issues"
    incident = payload["incident"]
    title = (
        f"[{incident['severity']}] {incident['source']} incident on {incident['asset'] or 'unknown-asset'} "
        f"#{incident['id'][:8]}"
    )[:240]
    labels = [
        item.strip()
        for item in (config.GITHUB_ISSUE_LABELS or "").split(",")
        if item.strip()
    ]
    body = (
        f"Event type: {payload['event_type']}\n"
        f"Event key: {payload['event_key']}\n"
        f"Idempotency fingerprint: `{idempotency_key}`\n"
        f"Generated at: {payload['generated_at']}\n\n"
        f"Incident ID: {incident['id']}\n"
        f"Source: {incident['source']}\n"
        f"Severity: {incident['severity']}\n"
        f"Status: {incident['status']}\n"
        f"Asset: {incident['asset'] or 'n/a'}\n\n"
        f"Message:\n{incident['message']}\n"
    )
    _request_json(
        method="POST",
        url=url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {config.GITHUB_TOKEN}",
            "X-GitHub-Api-Version": "2022-11-28",
            "Idempotency-Key": idempotency_key,
        },
        payload={"title": title, "body": body, "labels": labels},
    )


def _deliver_to_channel(*, channel: str, payload: dict[str, Any], idempotency_key: str):
    if channel == "webhook":
        _send_webhook(payload=payload, idempotency_key=idempotency_key)
        return
    if channel == "telegram":
        _send_telegram(payload=payload, idempotency_key=idempotency_key)
        return
    if channel == "github":
        _send_github_issue(payload=payload, idempotency_key=idempotency_key)
        return
    raise ValueError(f"Unsupported outbound channel: {channel}")


def _serialize_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _dispatch_with_retry(
    db: Session,
    *,
    channel: str,
    event_type: str,
    event_key: str,
    payload: dict[str, Any],
):
    fingerprint = _fingerprint_for_delivery(channel=channel, event_key=event_key)
    item = get_outbound_event_by_fingerprint(db, fingerprint)
    if item and item.status == "sent":
        return

    if not item:
        item = create_outbound_event(
            db,
            channel=channel,
            event_type=event_type,
            fingerprint=fingerprint,
            payload=_serialize_payload(payload),
        )

    max_attempts = max(1, int(config.OUTBOUND_RETRY_MAX_ATTEMPTS))
    remaining = max(0, max_attempts - int(item.attempts or 0))
    if remaining == 0:
        return

    for _ in range(remaining):
        try:
            _deliver_to_channel(
                channel=channel,
                payload=payload,
                idempotency_key=fingerprint,
            )
            mark_outbound_attempt_sent(db, item)
            return
        except Exception as exc:
            mark_outbound_attempt_failed(db, item, error_message=str(exc))
            record_exception(
                db,
                source="outbound",
                operation=f"deliver_{channel}",
                exc=exc,
                severity="MEDIUM",
                context={"event_type": event_type, "event_key": event_key},
            )


def dispatch_incident_event(
    db: Session,
    *,
    incident,
    event_type: str,
    event_key: str,
):
    if not _can_notify_for_severity(getattr(incident, "severity", "MEDIUM")):
        return

    channels = _configured_channels()
    if not channels:
        return

    payload = {
        "event_type": event_type,
        "event_key": event_key,
        "generated_at": _utc_now_iso(),
        "incident": {
            "id": str(incident.id),
            "source": incident.source,
            "severity": incident.severity,
            "status": incident.status,
            "asset": _infer_asset(incident.message),
            "message": incident.message,
            "detected_at": incident.detected_at.isoformat() if incident.detected_at else None,
        },
    }

    for channel in channels:
        try:
            _dispatch_with_retry(
                db,
                channel=channel,
                event_type=event_type,
                event_key=event_key,
                payload=payload,
            )
        except Exception as exc:
            record_exception(
                db,
                source="outbound",
                operation=f"dispatch_{channel}",
                exc=exc,
                severity="MEDIUM",
                context={"event_type": event_type, "event_key": event_key},
            )
