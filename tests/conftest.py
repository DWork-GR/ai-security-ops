import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
TEST_DB_PATH = BACKEND_DIR / "app" / "database" / "test_ai_secops.db"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ["DATABASE_URL"] = f"sqlite:///{TEST_DB_PATH.as_posix()}"
os.environ["GEMINI_API_KEY"] = ""
os.environ["LLM_PROVIDER"] = "none"
os.environ["RBAC_ENABLED"] = "false"
os.environ["RBAC_KEYS"] = ""
os.environ["INTEGRATION_AUTH_REQUIRED"] = "false"
os.environ["CHAT_AUTH_REQUIRED"] = "false"
os.environ["STREAM_ALLOW_QUERY_USER_KEY"] = "true"
os.environ["SCAN_WORKER_ENABLED"] = "false"

from app.database.db import Base, engine  # noqa: E402
from app.database.seed_cves import seed as seed_cves  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def reset_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    seed_cves()
    yield


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client
