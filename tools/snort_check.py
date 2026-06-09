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


def _run(command: list[str]) -> tuple[int, str]:
    completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=8)
    output = "\n".join(part for part in [completed.stdout, completed.stderr] if part)
    return completed.returncode, output.strip()


def main() -> int:
    _load_dotenv(Path(".env"))
    snort_binary = os.getenv("SNORT_BINARY", "snort")
    snort_config = os.getenv("SNORT_CONFIG", r"C:\Snort\etc\snort.conf")
    alert_file = os.getenv("SNORT_ALERT_FILE", r"C:\Snort\log\alert.fast")

    print(f"SNORT_BINARY={snort_binary}", flush=True)
    print(f"SNORT_CONFIG={snort_config}", flush=True)
    print(f"SNORT_ALERT_FILE={alert_file}", flush=True)
    print(f"binary_exists={Path(snort_binary).exists()}", flush=True)
    print(f"config_exists={Path(snort_config).exists()}", flush=True)
    print(f"log_dir_exists={Path(alert_file).parent.exists()}", flush=True)

    for command in ([snort_binary, "-V"], [snort_binary, "-W"], [snort_binary, "-T", "-c", snort_config]):
        print(f"\n> {' '.join(command)}", flush=True)
        try:
            code, output = _run(command)
        except Exception as exc:
            print(f"failed: {exc}", flush=True)
            continue
        print(f"exit_code={code}", flush=True)
        if output:
            print(output[:4000], flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
