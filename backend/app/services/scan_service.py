import time
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import NMAP_ALLOW_SOCKET_FALLBACK
from app.database.repository import (
    add_scan_finding,
    create_scan_run,
    list_open_ports_for_scan_run,
    search_cves,
    upsert_asset,
    get_latest_scan_run_for_target,
)
from app.integrations.nmap.scanner import discover_open_tcp_ports, inspect_open_tcp_services, is_nmap_available
from app.services.incident_service import calculate_risk_score, correlate_incident

DEFAULT_TCP_PORTS = [
    21,
    22,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    3306,
    3389,
    5432,
    6379,
    8080,
    8443,
]

PORT_TO_SERVICE = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "rpc",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}

SERVICE_HINTS = {
    "ftp": ["ftp", "vsftpd", "file transfer"],
    "ssh": ["ssh", "openssh", "auth bypass"],
    "http": ["apache", "nginx", "http", "path traversal", "sql injection"],
    "https": ["apache", "nginx", "tls", "https"],
    "smb": ["smb", "windows", "eternalblue", "server message block"],
    "mysql": ["mysql", "mariadb", "sql injection"],
    "postgresql": ["postgres", "postgresql", "sql injection"],
    "rdp": ["rdp", "remote desktop", "windows"],
    "redis": ["redis", "unauthenticated"],
    "dns": ["dns", "bind", "cache poisoning"],
    "smtp": ["smtp", "mail", "postfix", "exchange"],
}

SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

ASSET_CRITICALITY_BONUS = {
    "LOW": -8.0,
    "MEDIUM": 0.0,
    "HIGH": 7.0,
    "CRITICAL": 12.0,
}


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _normalize_ports(ports: list[int] | None) -> list[int]:
    source = ports if ports else DEFAULT_TCP_PORTS
    normalized: list[int] = []
    for raw in source:
        value = int(raw)
        if value < 1 or value > 65535:
            raise ValueError(f"Invalid port: {value}")
        if value not in normalized:
            normalized.append(value)
    if len(normalized) > 64:
        raise ValueError("Too many ports requested. Maximum is 64.")
    return normalized


def _resolve_severity(cves) -> str:
    top = "MEDIUM"
    for cve in cves:
        sev = (cve.severity or "MEDIUM").upper().strip()
        if SEVERITY_RANK.get(sev, 2) > SEVERITY_RANK.get(top, 2):
            top = sev
    return top


def _match_cves_for_service(db: Session, service: str, limit: int = 3):
    hints = SERVICE_HINTS.get(service, [service])
    matched = []
    seen = set()
    for hint in hints:
        candidates = search_cves(db, query=hint, limit=limit * 3)
        for candidate in candidates:
            if candidate.cve_id in seen:
                continue
            seen.add(candidate.cve_id)
            matched.append(candidate)
            if len(matched) >= limit:
                return matched
    return matched


def _apply_asset_criticality_bonus(risk_score: float, criticality: str) -> float:
    bonus = ASSET_CRITICALITY_BONUS.get((criticality or "MEDIUM").upper(), 0.0)
    value = max(0.0, min(100.0, risk_score + bonus))
    return round(value, 1)


def run_active_scan(
    db: Session,
    *,
    target: str,
    ports: list[int] | None = None,
    timeout_ms: int = 250,
    source: str = "openvas",
):
    if timeout_ms < 50 or timeout_ms > 3000:
        raise ValueError("timeout_ms must be between 50 and 3000")

    scan_ports = _normalize_ports(ports)
    normalized_source = (source or "openvas").lower().strip() or "openvas"
    task_id = str(uuid.uuid4())
    started_at = _utc_now_naive()

    baseline = get_latest_scan_run_for_target(db, target)
    baseline_open_ports = (
        list_open_ports_for_scan_run(db, baseline.id) if baseline else []
    )

    started_perf = time.perf_counter()
    service_overrides: dict[int, str] = {}
    script_notes_by_port: dict[int, list[str]] = {}

    if normalized_source in {"nmap", "openvas"} and is_nmap_available():
        open_ports, service_overrides, script_notes_by_port, discovery_engine = inspect_open_tcp_services(
            target=target,
            ports=scan_ports,
            timeout_ms=timeout_ms,
            include_vuln_scripts=normalized_source == "openvas",
        )
    else:
        if normalized_source in {"nmap", "openvas"} and not NMAP_ALLOW_SOCKET_FALLBACK:
            raise RuntimeError(
                "Real scanning is enforced, but 'nmap' is not available. Install nmap or set NMAP_ALLOW_SOCKET_FALLBACK=true."
            )
        open_ports, discovery_engine = discover_open_tcp_ports(
            target=target,
            ports=scan_ports,
            timeout_ms=timeout_ms,
        )
    duration_ms = int((time.perf_counter() - started_perf) * 1000)
    finished_at = _utc_now_naive()

    new_open_ports = sorted(set(open_ports) - set(baseline_open_ports))
    closed_open_ports = sorted(set(baseline_open_ports) - set(open_ports))

    asset = upsert_asset(db, ip=target)

    profile_prefix = "tcp"
    if normalized_source != "openvas":
        profile_prefix = f"{normalized_source}-tcp"

    scan_run = create_scan_run(
        db,
        task_id=task_id,
        target_ip=target,
        scan_profile=f"{profile_prefix}-default" if not ports else f"{profile_prefix}-custom",
        status="completed",
        scanned_ports=len(scan_ports),
        open_ports_count=len(open_ports),
        duration_ms=duration_ms,
        started_at=started_at,
        finished_at=finished_at,
    )

    findings = []
    incidents_created = 0
    incidents_updated = 0

    for port in open_ports:
        service = service_overrides.get(port) or PORT_TO_SERVICE.get(port, "unknown")
        cves = _match_cves_for_service(db, service=service)
        cve_refs = [item.cve_id for item in cves]
        severity = _resolve_severity(cves)
        max_cvss = max((item.cvss for item in cves), default=0.0)
        base_risk = calculate_risk_score(severity=severity, source=normalized_source, status="new")
        risk = _apply_asset_criticality_bonus(base_risk, asset.criticality)
        script_notes = script_notes_by_port.get(port, [])
        detail_suffix_en = ""
        detail_suffix_uk = ""
        if script_notes:
            notes = " | ".join(script_notes[:2])
            detail_suffix_en = f" Evidence: {notes}."
            detail_suffix_uk = f" Доказ: {notes}."
        summary_en = f"Potential exposure on {target}:{port}/tcp ({service}).{detail_suffix_en}"
        summary_uk = f"Ймовірна вразливість на {target}:{port}/tcp ({service}).{detail_suffix_uk}"

        finding = {
            "port": port,
            "protocol": "tcp",
            "service": service,
            "severity": severity,
            "risk_score": risk,
            "cvss_max": float(max_cvss),
            "cve_references": cve_refs,
            "summary_en": summary_en,
            "summary_uk": summary_uk,
        }
        findings.append(finding)

        add_scan_finding(
            db,
            scan_run_id=scan_run.id,
            port=port,
            protocol="tcp",
            service=service,
            severity=severity,
            risk_score=risk,
            cvss_max=float(max_cvss),
            cve_refs=cve_refs,
            summary_en=summary_en,
            summary_uk=summary_uk,
            fingerprint=f"{target}:{port}/tcp:{service}",
        )

        incident_message = (
            f"{normalized_source.upper()} active scan finding on {target}:{port}/tcp ({service}) "
            f"severity={severity}; cves={','.join(cve_refs) if cve_refs else 'n/a'}"
        )
        _, created = correlate_incident(
            db,
            source=normalized_source,
            message=incident_message,
            severity=severity,
            asset=target,
            signature=f"{target}:{port}:{service}:{','.join(cve_refs)}",
            actor_role="scanner",
        )
        if created:
            incidents_created += 1
        else:
            incidents_updated += 1

    if not findings:
        _, created = correlate_incident(
            db,
            source=normalized_source,
            message=(
                f"{normalized_source.upper()} active scan completed for {target}: "
                "no open ports from selected profile."
            ),
            severity="LOW",
            asset=target,
            signature=f"{target}:no_open_ports",
            actor_role="scanner",
        )
        if created:
            incidents_created += 1
        else:
            incidents_updated += 1

    return {
        "task_id": task_id,
        "scanner": normalized_source,
        "discovery_engine": discovery_engine,
        "target": target,
        "status": "completed",
        "scan_profile": scan_run.scan_profile,
        "scanned_ports": len(scan_ports),
        "open_ports": open_ports,
        "duration_ms": duration_ms,
        "findings": findings,
        "incidents_created": incidents_created,
        "incidents_updated": incidents_updated,
        "baseline_scan_task_id": baseline.task_id if baseline else None,
        "new_open_ports": new_open_ports,
        "closed_open_ports": closed_open_ports,
    }
