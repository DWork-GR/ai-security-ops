from pathlib import Path

ALERTS_FILE = Path(__file__).parent / "alerts" / "alert.fast"


def parse_alerts():
    if not ALERTS_FILE.exists():
        return []

    raw = ALERTS_FILE.read_text(encoding="utf-8")
    blocks = raw.strip().split("\n\n")

    alerts = []
    for block in blocks:
        lines = block.splitlines()
        if len(lines) < 2:
            continue

        message = lines[0].strip()
        priority_line = lines[1]

        if "Priority" in priority_line:
            try:
                priority = int(priority_line.split(":")[1].strip(" ]"))
            except (ValueError, IndexError):
                continue

            alerts.append(
                {
                    "message": message,
                    "priority": priority,
                }
            )

    return alerts
