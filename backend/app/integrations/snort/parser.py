from pathlib import Path
import re

ALERTS_FILE = Path(__file__).parent / "alerts" / "alert.fast"
MESSAGE_PATTERN = re.compile(r"\[\*\*\]\s*(?:\[\d+:\d+:\d+\]\s*)?(.*?)\s*\[\*\*\]")
PRIORITY_PATTERN = re.compile(r"\[Priority:\s*(\d+)\]")
IP_PAIR_PATTERN = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})")


def parse_alerts():
    if not ALERTS_FILE.exists():
        return []

    raw = ALERTS_FILE.read_text(encoding="utf-8")
    blocks = raw.strip().split("\n\n")

    alerts = []
    for block in blocks:
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if not lines:
            continue

        message_match = MESSAGE_PATTERN.search(lines[0])
        priority_match = PRIORITY_PATTERN.search(block)
        if not message_match or not priority_match:
            continue

        ip_match = IP_PAIR_PATTERN.search(block)
        src_ip = ip_match.group(1) if ip_match else None
        dst_ip = ip_match.group(2) if ip_match else None

        alerts.append(
            {
                "message": message_match.group(1).strip(),
                "priority": int(priority_match.group(1)),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
            }
        )

    return alerts
