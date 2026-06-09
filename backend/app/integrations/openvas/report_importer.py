import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.database.repository import add_scan_finding, create_scan_run, upsert_asset
from app.services.incident_service import calculate_risk_score, correlate_incident

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _children_by_name(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(element) if _local_name(child.tag) == name]


def _first_text(element: ET.Element, *names: str) -> str:
    for name in names:
        for child in _children_by_name(element, name):
            text = "".join(child.itertext()).strip()
            if text:
                return text
    return ""


def _normalize_severity(value: str | None, cvss: float = 0.0) -> str:
    raw = (value or "").strip().upper()
    if raw in SEVERITY_RANK:
        return raw
    if raw in {"LOG", "DEBUG", "NONE", "FALSE POSITIVE"}:
        return "LOW"
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def _parse_cvss(value: str | float | int | None) -> float:
    try:
        return max(0.0, min(10.0, float(value or 0.0)))
    except (TypeError, ValueError):
        return 0.0


def _parse_port(raw: str | int | None) -> tuple[int, str]:
    if isinstance(raw, int):
        return raw, "tcp"
    text = (raw or "").strip()
    match = re.search(r"(\d+)\s*/\s*(tcp|udp)", text, re.IGNORECASE)
    if match:
        return int(match.group(1)), match.group(2).lower()
    match = re.search(r"\b(\d{1,5})\b", text)
    if match:
        return int(match.group(1)), "tcp"
    return 0, "tcp"


def _split_cves(raw: str | None) -> list[str]:
    if not raw:
        return []
    return sorted({item.upper() for item in re.findall(r"CVE-\d{4}-\d{4,}", raw, re.IGNORECASE)})


def parse_greenbone_report_xml(report_xml: str, default_target: str | None = None) -> list[dict[str, Any]]:
    root = ET.fromstring(report_xml)
    findings: list[dict[str, Any]] = []

    for result in root.iter():
        if _local_name(result.tag) != "result":
            continue

        host = _first_text(result, "host") or default_target or ""
        port, protocol = _parse_port(_first_text(result, "port"))
        name = _first_text(result, "name")
        description = _first_text(result, "description")
        threat = _first_text(result, "threat")
        cvss = _parse_cvss(_first_text(result, "severity"))
        service = ""
        cves: list[str] = []

        for nvt in _children_by_name(result, "nvt"):
            name = name or _first_text(nvt, "name")
            service = service or _first_text(nvt, "family")
            cvss = max(cvss, _parse_cvss(_first_text(nvt, "cvss_base")))
            cves.extend(_split_cves(_first_text(nvt, "cve")))

        if not name:
            continue

        severity = _normalize_severity(threat, cvss)
        findings.append(
            {
                "host": host,
                "port": port,
                "protocol": protocol,
                "service": service or "openvas",
                "name": name,
                "severity": severity,
                "cvss": cvss,
                "cves": sorted(set(cves)),
                "description": description,
            }
        )

    return findings


def import_openvas_findings(
    db: Session,
    *,
    target: str | None,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    normalized_findings = [item for item in findings if (item.get("name") or "").strip()]
    task_id = str(uuid.uuid4())
    now = _utc_now_naive()
    target_ip = (target or "").strip() or (normalized_findings[0].get("host") or "unknown")

    upsert_asset(db, ip=target_ip)
    scan_run = create_scan_run(
        db,
        task_id=task_id,
        target_ip=target_ip,
        scan_profile="openvas-report-import",
        status="completed",
        scanned_ports=len(normalized_findings),
        open_ports_count=len({int(item.get("port") or 0) for item in normalized_findings if int(item.get("port") or 0) > 0}),
        duration_ms=0,
        started_at=now,
        finished_at=now,
    )

    incidents_created = 0
    incidents_updated = 0

    for item in normalized_findings:
        host = (item.get("host") or target_ip).strip()
        port = int(item.get("port") or 0)
        protocol = (item.get("protocol") or "tcp").strip().lower()
        service = (item.get("service") or "openvas").strip().lower()
        name = (item.get("name") or "OpenVAS finding").strip()
        severity = _normalize_severity(item.get("severity"), _parse_cvss(item.get("cvss")))
        cvss = _parse_cvss(item.get("cvss"))
        cves = [str(cve).upper() for cve in (item.get("cves") or []) if str(cve).strip()]
        description = (item.get("description") or "").strip()
        risk = calculate_risk_score(severity=severity, source="openvas", status="new")
        location = f"{host}:{port}/{protocol}" if port else host
        summary_en = f"OpenVAS finding on {location}: {name}."
        if description:
            summary_en = f"{summary_en} {description[:500]}"
        summary_uk = f"OpenVAS знахідка на {location}: {name}."

        add_scan_finding(
            db,
            scan_run_id=scan_run.id,
            port=port,
            protocol=protocol,
            service=service,
            severity=severity,
            risk_score=risk,
            cvss_max=cvss,
            cve_refs=cves,
            summary_en=summary_en,
            summary_uk=summary_uk,
            fingerprint=f"{host}:{port}/{protocol}:{name}:{','.join(cves)}",
        )

        message = (
            f"OpenVAS report finding on {location}: {name} "
            f"severity={severity}; cvss={cvss}; cves={','.join(cves) if cves else 'n/a'}"
        )
        _, created = correlate_incident(
            db,
            source="openvas",
            message=message,
            severity=severity,
            asset=host,
            signature=f"{host}:{port}:{name}:{','.join(cves)}",
            actor_role="integration",
        )
        if created:
            incidents_created += 1
        else:
            incidents_updated += 1

    return {
        "accepted": len(normalized_findings),
        "incidents_created": incidents_created,
        "incidents_updated": incidents_updated,
        "scan_task_id": task_id,
    }
