import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.database.repository import upsert_cves


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_description(cve: dict) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if (item.get("lang") or "").lower() == "en" and item.get("value"):
            return item["value"].strip()
    for item in descriptions:
        if item.get("value"):
            return item["value"].strip()
    return "No description provided."


def _extract_score_and_severity(cve: dict) -> tuple[float, str]:
    metrics = cve.get("metrics") or {}
    metric_keys = [
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]
    for key in metric_keys:
        rows = metrics.get(key) or []
        if not rows:
            continue
        first = rows[0]
        cvss_data = first.get("cvssData") or {}
        score = float(cvss_data.get("baseScore", 0.0))
        severity = (
            cvss_data.get("baseSeverity")
            or first.get("baseSeverity")
            or _severity_from_cvss(score)
        )
        return score, str(severity).upper().strip()
    return 0.0, "LOW"


def _extract_mitigation(cve: dict, default_mitigation: str) -> str:
    references = cve.get("references") or []
    urls = []
    for item in references[:3]:
        url = (item.get("url") or "").strip()
        if url:
            urls.append(url)
    if not urls:
        return default_mitigation
    joined = "; ".join(urls)
    return f"{default_mitigation} References: {joined}"


def import_nvd_json(
    db: Session,
    *,
    file_path: str,
    default_mitigation: str,
):
    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    payload = json.loads(path.read_text(encoding="utf-8"))
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("Invalid NVD JSON: expected 'vulnerabilities' array")

    records = []
    skipped = 0
    for row in vulnerabilities:
        cve = row.get("cve") or {}
        cve_id = (cve.get("id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            skipped += 1
            continue

        score, severity = _extract_score_and_severity(cve)
        records.append(
            {
                "cve_id": cve_id,
                "cvss": score,
                "severity": severity,
                "description": _extract_description(cve),
                "mitigation": _extract_mitigation(cve, default_mitigation),
            }
        )

    created, updated = upsert_cves(db, records)
    return {
        "imported_total": len(records),
        "created": created,
        "updated": updated,
        "skipped": skipped,
    }
