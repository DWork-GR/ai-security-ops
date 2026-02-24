from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.api.rbac import require_roles
from app.core.schemas import OperationsReportResponse
from app.database.db import get_db
from app.database.repository import get_error_summary_stats, get_incident_summary_stats, list_incidents
from app.services.incident_service import calculate_risk_score

router = APIRouter(prefix="/reports", tags=["reports"])


def _utc_now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _build_reports(db: Session):
    stats = get_incident_summary_stats(db)
    error_stats = get_error_summary_stats(db)
    latest = list_incidents(db, limit=5)
    all_for_risk = list_incidents(db, limit=500)

    if all_for_risk:
        risk_values = [
            calculate_risk_score(
                severity=item.severity,
                source=item.source,
                status=item.status,
            )
            for item in all_for_risk
        ]
        avg_risk = round(sum(risk_values) / len(risk_values), 1)
        high_risk = sum(1 for value in risk_values if value >= 80)
    else:
        avg_risk = 0.0
        high_risk = 0

    latest_rows = [
        (
            f"- {item.detected_at.isoformat()} | {item.severity} | {item.status} | "
            f"{item.source} | risk={calculate_risk_score(severity=item.severity, source=item.source, status=item.status)}"
        )
        for item in latest
    ] or ["- No incidents available."]

    report_en = "\n".join(
        [
            "SOC Operations Summary (EN)",
            f"Generated at: {_utc_now_naive().isoformat()}",
            f"Total incidents: {stats['total_incidents']}",
            f"Open incidents: {stats['open_incidents']}",
            f"Critical open incidents: {stats['critical_open_incidents']}",
            f"Incidents in last 24h: {stats['incidents_last_24h']}",
            f"Average risk score: {avg_risk}",
            f"High-risk incidents (>=80): {high_risk}",
            f"Unique error events: {error_stats['total_errors']}",
            f"Error occurrences: {error_stats['total_occurrences']}",
            "",
            "Top recent incidents:",
            *latest_rows,
        ]
    )

    report_uk = "\n".join(
        [
            "Підсумок SOC Операцій (UK)",
            f"Згенеровано: {_utc_now_naive().isoformat()}",
            f"Усього інцидентів: {stats['total_incidents']}",
            f"Відкритих інцидентів: {stats['open_incidents']}",
            f"Критичних відкритих: {stats['critical_open_incidents']}",
            f"Інцидентів за 24 години: {stats['incidents_last_24h']}",
            f"Середній risk score: {avg_risk}",
            f"Інцидентів high-risk (>=80): {high_risk}",
            f"Унікальних error events: {error_stats['total_errors']}",
            f"Усього error occurrences: {error_stats['total_occurrences']}",
            "",
            "Останні інциденти:",
            *latest_rows,
        ]
    )

    return report_en, report_uk


@router.get("/operations", response_model=OperationsReportResponse)
def operations_report(
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("manager", "admin")),
):
    report_en, report_uk = _build_reports(db)
    return OperationsReportResponse(
        generated_at=_utc_now_naive(),
        report_en=report_en,
        report_uk=report_uk,
    )


@router.get("/operations/markdown", response_class=PlainTextResponse)
def operations_report_markdown(
    db: Session = Depends(get_db),
    _: str = Depends(require_roles("manager", "admin")),
):
    report_en, report_uk = _build_reports(db)
    markdown = (
        "# SOC Operations Report\n\n"
        "## English\n\n"
        "```\n"
        f"{report_en}\n"
        "```\n\n"
        "## Українською\n\n"
        "```\n"
        f"{report_uk}\n"
        "```\n"
    )
    return markdown
