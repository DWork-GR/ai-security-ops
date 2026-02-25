import hmac

from fastapi import Header, HTTPException

from app.config import INTEGRATION_API_KEY, INTEGRATION_AUTH_REQUIRED


def require_integration_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    if not INTEGRATION_AUTH_REQUIRED:
        return

    if not INTEGRATION_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Integration authentication is enabled but INTEGRATION_API_KEY is not configured",
        )

    provided = (x_api_key or "").strip()
    if not provided:
        raise HTTPException(status_code=401, detail="X-API-Key is required")

    if not hmac.compare_digest(provided, INTEGRATION_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid integration API key")
