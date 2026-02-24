def analyze_alerts_expert(alerts: list[str]) -> str:
    if not alerts:
        return (
            "[EN] Rule-Based SOC Analysis\n"
            "Threat Signals:\n"
            "- No critical threats detected.\n\n"
            "Recommended Actions:\n"
            "- Continue monitoring.\n\n"
            "[UK] Rule-Based SOC Аналіз\n"
            "Ознаки Загрози:\n"
            "- Критичних загроз не виявлено.\n\n"
            "Рекомендовані Дії:\n"
            "- Продовжуйте моніторинг."
        )

    findings_en: list[str] = []
    findings_uk: list[str] = []
    recommendations_en: list[str] = []
    recommendations_uk: list[str] = []

    for alert in alerts:
        alert_lower = alert.lower()
        if "sql injection" in alert_lower:
            findings_en.append("SQL injection pattern detected in IDS traffic.")
            findings_uk.append("Виявлено патерн SQL injection у IDS-трафіку.")
            recommendations_en.extend(
                [
                    "Block suspicious source IP addresses at the edge firewall.",
                    "Review web access logs and WAF events for matching timestamps.",
                    "Enforce parameterized queries in affected applications.",
                ]
            )
            recommendations_uk.extend(
                [
                    "Заблокуйте підозрілі IP-адреси джерела на edge firewall.",
                    "Перевірте web-логи та події WAF за відповідними таймштампами.",
                    "Застосуйте parameterized queries у вразливих застосунках.",
                ]
            )
        elif "port scan" in alert_lower:
            findings_en.append("Reconnaissance activity detected (port scan).")
            findings_uk.append("Виявлено розвідувальну активність (port scan).")
            recommendations_en.extend(
                [
                    "Apply rate-limiting and temporary deny-list for scanner IPs.",
                    "Verify exposed services and close unused ports.",
                ]
            )
            recommendations_uk.extend(
                [
                    "Увімкніть rate-limiting і тимчасовий deny-list для IP сканера.",
                    "Перевірте відкриті сервіси та закрийте невикористані порти.",
                ]
            )
        else:
            findings_en.append(f"Critical IDS alert detected: {alert}")
            findings_uk.append(f"Виявлено критичний IDS-алерт: {alert}")
            recommendations_en.append("Escalate to SOC analyst for triage.")
            recommendations_uk.append("Ескалюйте інцидент аналітику SOC для triage.")

    unique_recommendations_en = sorted(set(recommendations_en))
    unique_recommendations_uk = sorted(set(recommendations_uk))

    lines: list[str] = []
    lines.append("[EN] Rule-Based SOC Analysis")
    lines.append("Threat Signals:")
    for finding in findings_en:
        lines.append(f"- {finding}")
    lines.append("")
    lines.append("Recommended Actions:")
    for recommendation in unique_recommendations_en:
        lines.append(f"- {recommendation}")

    lines.append("")
    lines.append("[UK] Rule-Based SOC Аналіз")
    lines.append("Ознаки Загрози:")
    for finding in findings_uk:
        lines.append(f"- {finding}")
    lines.append("")
    lines.append("Рекомендовані Дії:")
    for recommendation in unique_recommendations_uk:
        lines.append(f"- {recommendation}")

    return "\n".join(lines)
