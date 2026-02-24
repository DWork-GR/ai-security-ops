from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class ChatRequest(BaseModel):
    message: str
    user_id: Optional[str] = None


class ChatResponse(BaseModel):
    intent: str
    response: Optional[str] = None
    cves: Optional[List[dict]] = None


class OpenVASScanRequest(BaseModel):
    target: str


class OpenVASScanResponse(BaseModel):
    task_id: str
    target: str
    status: str


class SnortAlertIn(BaseModel):
    message: str
    priority: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    detected_at: Optional[datetime] = None


class SnortAlertsIn(BaseModel):
    alerts: List[SnortAlertIn]


class IncidentOut(BaseModel):
    id: str
    source: str
    message: str
    severity: str
    status: str
    detected_at: datetime


class IncidentListResponse(BaseModel):
    items: List[IncidentOut]
