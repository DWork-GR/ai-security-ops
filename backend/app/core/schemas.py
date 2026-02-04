from pydantic import BaseModel
from typing import Optional


class ChatRequest(BaseModel):
    message: str
    user_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    intent: str
    entities: dict
