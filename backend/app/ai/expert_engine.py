def analyze_alerts_expert(alerts: list[str]) -> str:
    if not alerts:
        return "No critical threats were detected."

    findings = []
    recommendations = []

    for alert in alerts:
        alert_lower = alert.lower()
        if "sql injection" in alert_lower:
            findings.append("SQL injection pattern detected in IDS traffic.")
            recommendations.extend(
                [
                    "Block suspicious source IP addresses at the edge firewall.",
                    "Review web access logs and WAF events for matching timestamps.",
                    "Enforce parameterized queries in affected applications.",
                ]
            )
        elif "port scan" in alert_lower:
            findings.append("Reconnaissance activity detected (port scan).")
            recommendations.extend(
                [
                    "Apply rate-limiting and temporary deny-list for scanner IPs.",
                    "Verify exposed services and close unused ports.",
                ]
            )
        else:
            findings.append(f"Critical IDS alert: {alert}")
            recommendations.append("Escalate to SOC analyst for triage.")

    unique_recommendations = sorted(set(recommendations))

    lines = ["SOC analysis summary:"]
    for finding in findings:
        lines.append(f"- {finding}")

    lines.append("")
    lines.append("Recommended actions:")
    for recommendation in unique_recommendations:
        lines.append(f"- {recommendation}")

    return "\n".join(lines)
