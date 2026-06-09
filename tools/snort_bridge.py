import argparse
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

MESSAGE_PATTERN = re.compile(r"\[\*\*\]\s*(?:\[\d+:\d+:\d+\]\s*)?(.*?)\s*\[\*\*\]")
PRIORITY_PATTERN = re.compile(r"\[Priority:\s*(\d+)\]")
IP_PAIR_PATTERN = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?\s*->\s*(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?"
)


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _parse_alert_block(block: str) -> dict | None:
    lines = [line.strip() for line in block.splitlines() if line.strip()]
    if not lines:
        return None

    message_match = MESSAGE_PATTERN.search(lines[0])
    priority_match = PRIORITY_PATTERN.search(block)
    if not message_match or not priority_match:
        return None

    ip_match = IP_PAIR_PATTERN.search(block)
    return {
        "message": message_match.group(1).strip(),
        "priority": int(priority_match.group(1)),
        "src_ip": ip_match.group(1) if ip_match else None,
        "dst_ip": ip_match.group(2) if ip_match else None,
    }


def _read_new_blocks(path: Path, offset: int) -> tuple[list[str], int]:
    if not path.exists():
        return [], offset

    size = path.stat().st_size
    if size < offset:
        offset = 0

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        chunk = handle.read()
        offset = handle.tell()

    blocks = [block.strip() for block in chunk.split("\n\n") if block.strip()]
    if len(blocks) <= 1:
        blocks = [line.strip() for line in chunk.splitlines() if line.strip()]
    return blocks, offset


def _post_alerts(api_base: str, api_key: str, alerts: list[dict]) -> dict:
    payload = json.dumps({"alerts": alerts}).encode("utf-8")
    request = urllib.request.Request(
        f"{api_base.rstrip('/')}/integrations/snort/alerts",
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-API-Key": api_key,
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    _load_dotenv(Path(".env"))
    parser = argparse.ArgumentParser(description="Forward Snort alert.fast events into AI Security Ops.")
    parser.add_argument(
        "--file",
        default=os.getenv("SNORT_ALERT_FILE", "backend/app/integrations/snort/alerts/alert.fast"),
        help="Path to Snort alert_fast output file.",
    )
    parser.add_argument("--api-base", default="http://127.0.0.1:8000", help="Backend API base URL.")
    parser.add_argument("--api-key", default=os.getenv("INTEGRATION_API_KEY", ""), help="Value for X-API-Key.")
    parser.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds.")
    parser.add_argument("--from-start", action="store_true", help="Send existing alerts instead of only new ones.")
    args = parser.parse_args()
    if not args.api_key:
        parser.error("--api-key is required when INTEGRATION_API_KEY is not set in .env")

    path = Path(args.file)
    offset = 0 if args.from_start or not path.exists() else path.stat().st_size
    print(f"Watching {path} -> {args.api_base}/integrations/snort/alerts")

    while True:
        blocks, offset = _read_new_blocks(path, offset)
        alerts = [alert for block in blocks if (alert := _parse_alert_block(block))]
        if alerts:
            try:
                result = _post_alerts(args.api_base, args.api_key, alerts)
                print(f"sent={len(alerts)} result={result}")
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                print(f"send failed: {exc}")
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
