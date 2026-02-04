from app.integrations.snort.parser import parse_alerts


def get_critical_alerts():
    return [a for a in parse_alerts() if a["priority"] == 1]
