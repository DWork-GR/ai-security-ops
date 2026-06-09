import argparse
import os
from datetime import datetime
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def main() -> int:
    _load_dotenv(Path(".env"))
    parser = argparse.ArgumentParser(description="Append a Snort-compatible test alert.")
    parser.add_argument(
        "--file",
        default=os.getenv("SNORT_ALERT_FILE", "backend/app/integrations/snort/alerts/alert.fast"),
        help="Path to alert.fast.",
    )
    parser.add_argument("--src", default="192.168.56.10")
    parser.add_argument("--dst", default="127.0.0.1")
    parser.add_argument("--priority", type=int, default=1)
    parser.add_argument("--message", default="AI Security Ops test Snort alert")
    args = parser.parse_args()

    path = Path(args.file)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%m/%d-%H:%M:%S.%f")[:-3]
    line = (
        f'{stamp} [**] [1:1000001:1] {args.message} [**] '
        f'[Priority: {args.priority}] {{TCP}} {args.src}:4444 -> {args.dst}:80\n'
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
