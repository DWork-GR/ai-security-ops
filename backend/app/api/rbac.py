from fastapi import APIRouter, Depends, Header, HTTPException

from app.config import RBAC_ENABLED, RBAC_KEYS

ROLE_PRIORITY = {"analyst": 1, "manager": 2, "admin": 3}
router = APIRouter(prefix="/rbac", tags=["rbac"])


def _parse_rbac_keys(raw: str) -> dict[str, str]:
    mapping: dict[str, str] = {}
    if not raw:
        return mapping

    chunks = [part.strip() for part in raw.split(";") if part.strip()]
    for chunk in chunks:
        if ":" not in chunk:
            continue
        role, api_key = chunk.split(":", 1)
        role = role.strip().lower()
        api_key = api_key.strip()
        if role in ROLE_PRIORITY and api_key:
            mapping[api_key] = role
    return mapping


RBAC_KEY_TO_ROLE = _parse_rbac_keys(RBAC_KEYS)


def get_current_role(
    x_user_key: str | None = Header(default=None, alias="X-User-Key"),
) -> str:
    if not RBAC_ENABLED:
        return "admin"

    if not x_user_key:
        raise HTTPException(status_code=401, detail="X-User-Key is required")

    role = RBAC_KEY_TO_ROLE.get(x_user_key)
    if not role:
        raise HTTPException(status_code=401, detail="Invalid X-User-Key")
    return role


def require_roles(*allowed_roles: str):
    allowed = {role.lower() for role in allowed_roles}
    minimum_priority = min((ROLE_PRIORITY.get(role, 999) for role in allowed), default=999)

    def dependency(role: str = Depends(get_current_role)) -> str:
        if ROLE_PRIORITY.get(role, 0) < minimum_priority:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return role

    return dependency


def current_role_info(role: str = Depends(get_current_role)) -> dict[str, str | int]:
    return {
        "role": role,
        "priority": ROLE_PRIORITY.get(role, 0),
    }


@router.get("/me")
def rbac_me(info: dict[str, str | int] = Depends(current_role_info)):
    return info
