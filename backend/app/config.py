import os
from pathlib import Path

from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = ROOT_DIR / ".env"
DEFAULT_DB_PATH = ROOT_DIR / "backend" / "app" / "database" / "knowledge.db"

if ENV_FILE.exists():
    load_dotenv(ENV_FILE)
else:
    load_dotenv()


def _resolve_database_url(raw_url: str) -> str:
    if not raw_url:
        DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"

    if raw_url.startswith("sqlite:///"):
        sqlite_path = raw_url[len("sqlite:///") :]
        if sqlite_path == ":memory:":
            return raw_url

        is_windows_abs = len(sqlite_path) >= 2 and sqlite_path[1] == ":"
        is_posix_abs = sqlite_path.startswith("/")

        if is_windows_abs or is_posix_abs:
            resolved = Path(sqlite_path)
        else:
            resolved = (ROOT_DIR / sqlite_path).resolve()

        resolved.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{resolved.as_posix()}"

    return raw_url


GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
DATABASE_URL = _resolve_database_url(os.getenv("DATABASE_URL", ""))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://127.0.0.1:5500")
INTEGRATION_API_KEY = os.getenv("INTEGRATION_API_KEY", "")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "none").strip().lower()
OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://127.0.0.1:11434",
).rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b").strip()
OLLAMA_API_KEY = os.getenv("OLLAMA_API_KEY", "").strip()
RBAC_KEYS = os.getenv("RBAC_KEYS", "").strip()
RBAC_ENABLED = os.getenv("RBAC_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"} or bool(RBAC_KEYS)

OUTBOUND_WEBHOOK_URL = os.getenv("OUTBOUND_WEBHOOK_URL", "").strip()
OUTBOUND_WEBHOOK_TOKEN = os.getenv("OUTBOUND_WEBHOOK_TOKEN", "").strip()
OUTBOUND_RETRY_MAX_ATTEMPTS = int(os.getenv("OUTBOUND_RETRY_MAX_ATTEMPTS", "3"))
OUTBOUND_TIMEOUT_MS = int(os.getenv("OUTBOUND_TIMEOUT_MS", "4000"))
OUTBOUND_MIN_SEVERITY = os.getenv("OUTBOUND_MIN_SEVERITY", "HIGH").strip().upper() or "HIGH"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
GITHUB_REPO = os.getenv("GITHUB_REPO", "").strip()
GITHUB_ISSUE_LABELS = os.getenv("GITHUB_ISSUE_LABELS", "ai-security-ops,incident").strip()

SCAN_WORKER_ENABLED = os.getenv("SCAN_WORKER_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
SCAN_WORKER_POLL_INTERVAL_SEC = float(os.getenv("SCAN_WORKER_POLL_INTERVAL_SEC", "1.5"))
