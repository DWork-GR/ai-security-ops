from typing import List, Optional
from pydantic import BaseModel
from typing import Optional


class ChatRequest(BaseModel):
    message: str
    user_id: Optional[str] = None


class ChatResponse(BaseModel):
    intent: str
    response: Optional[str] = None
    cves: Optional[List[dict]] = None
