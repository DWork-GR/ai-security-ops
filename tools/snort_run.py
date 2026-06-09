import os
import subprocess
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
    snort_binary = os.getenv("SNORT_BINARY", "snort")
    snort_config = os.getenv("SNORT_CONFIG", r"C:\Snort\etc\snort.conf")
    snort_interface = os.getenv("SNORT_INTERFACE", "1")
    alert_file = Path(os.getenv("SNORT_ALERT_FILE", r"C:\Snort\log\alert.fast"))
    alert_file.parent.mkdir(parents=True, exist_ok=True)

    command = [
        snort_binary,
        "-A",
        "fast",
        "-q",
        "-i",
        snort_interface,
        "-c",
        snort_config,
        "-l",
        str(alert_file.parent),
    ]
    print(" ".join(command), flush=True)
    return subprocess.call(command)


if __name__ == "__main__":
    raise SystemExit(main())
