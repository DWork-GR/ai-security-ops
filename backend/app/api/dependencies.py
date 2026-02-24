from fastapi import Header, HTTPException

from app.config import INTEGRATION_API_KEY


def require_integration_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    if not INTEGRATION_API_KEY:
        return

    if x_api_key != INTEGRATION_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid integration API key")
