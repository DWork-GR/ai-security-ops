from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


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


class OpenVASActiveScanRequest(BaseModel):
    target: str
    ports: Optional[List[int]] = None
    timeout_ms: int = Field(default=250, ge=50, le=3000)


class ActiveScanFindingOut(BaseModel):
    port: int
    protocol: str
    service: str
    severity: str
    risk_score: float
    cvss_max: float
    cve_references: List[str]
    summary_en: str
    summary_uk: str


class ActiveScanResponse(BaseModel):
    task_id: str
    scanner: str
    discovery_engine: str
    target: str
    status: str
    scan_profile: str
    scanned_ports: int
    open_ports: List[int]
    duration_ms: int
    findings: List[ActiveScanFindingOut]
    incidents_created: int
    incidents_updated: int
    baseline_scan_task_id: Optional[str] = None
    new_open_ports: List[int] = Field(default_factory=list)
    closed_open_ports: List[int] = Field(default_factory=list)


class OpenVASFindingOut(ActiveScanFindingOut):
    pass


class OpenVASActiveScanResponse(ActiveScanResponse):
    pass


class NmapActiveScanRequest(BaseModel):
    target: str
    ports: Optional[List[int]] = None
    timeout_ms: int = Field(default=250, ge=50, le=3000)


class NmapActiveScanResponse(ActiveScanResponse):
    pass


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
    risk_score: float
    asset: Optional[str] = None


class IncidentListResponse(BaseModel):
    items: List[IncidentOut]


class IncidentStatusUpdateRequest(BaseModel):
    status: str = Field(..., description="new|triaged|investigating|mitigated|closed|false_positive")


class IncidentStatusUpdateResponse(BaseModel):
    item: IncidentOut


class IncidentAuditLogOut(BaseModel):
    id: str
    action: str
    old_status: Optional[str] = None
    new_status: Optional[str] = None
    actor_role: str
    actor_id: Optional[str] = None
    details: Optional[str] = None
    created_at: datetime


class IncidentAuditLogListResponse(BaseModel):
    items: List[IncidentAuditLogOut]


class IncidentSummaryStatsResponse(BaseModel):
    total_incidents: int
    open_incidents: int
    critical_open_incidents: int
    incidents_last_24h: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    by_source: Dict[str, int]


class OperationsReportResponse(BaseModel):
    generated_at: datetime
    report_en: str
    report_uk: str


class CVEOut(BaseModel):
    cve_id: str
    cvss: float
    severity: str
    description: str
    mitigation: str


class CVEListResponse(BaseModel):
    total: int
    items: List[CVEOut]


class CVESeedResponse(BaseModel):
    imported_total: int
    created: int
    updated: int
    source: str


class ErrorEventOut(BaseModel):
    id: str
    source: str
    operation: str
    error_type: str
    message: str
    severity: str
    fingerprint: str
    occurrences: int
    context: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime


class ErrorEventListResponse(BaseModel):
    items: List[ErrorEventOut]


class ErrorSummaryStatsResponse(BaseModel):
    total_errors: int
    errors_last_24h: int
    total_occurrences: int
    by_severity: Dict[str, int]
    by_source: Dict[str, int]
    by_type: Dict[str, int]


class OutboundEventOut(BaseModel):
    id: str
    channel: str
    event_type: str
    fingerprint: str
    status: str
    attempts: int
    last_error: Optional[str] = None
    first_attempt_at: Optional[datetime] = None
    last_attempt_at: Optional[datetime] = None
    sent_at: Optional[datetime] = None
    created_at: datetime


class OutboundEventListResponse(BaseModel):
    items: List[OutboundEventOut]


class OutboundSummaryStatsResponse(BaseModel):
    total_events: int
    sent_events: int
    success_rate_percent: float
    by_status: Dict[str, int]
    by_channel: Dict[str, int]


class AssetUpsertRequest(BaseModel):
    ip: str
    hostname: Optional[str] = None
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    criticality: Optional[str] = None
    environment: Optional[str] = None
    tags: Optional[str] = None


class AssetOut(BaseModel):
    id: str
    ip: str
    hostname: Optional[str] = None
    owner: Optional[str] = None
    business_unit: Optional[str] = None
    criticality: str
    environment: str
    tags: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime


class AssetListResponse(BaseModel):
    items: List[AssetOut]


class AssetDiscoveryOut(BaseModel):
    ip: str
    hostname: Optional[str] = None
    criticality: str
    environment: str
    last_seen_at: datetime
    latest_scan_at: Optional[datetime] = None
    latest_scan_profile: Optional[str] = None
    latest_open_ports: List[int] = Field(default_factory=list)


class AssetDiscoveryListResponse(BaseModel):
    items: List[AssetDiscoveryOut]


class ScanRunOut(BaseModel):
    task_id: str
    target_ip: str
    scan_profile: str
    status: str
    scanned_ports: int
    open_ports_count: int
    duration_ms: int
    started_at: datetime
    finished_at: datetime
    open_ports: List[int]


class ScanRunListResponse(BaseModel):
    items: List[ScanRunOut]


class ScanJobCreateRequest(BaseModel):
    target_ip: str
    scan_type: str = Field(
        default="quick",
        description="quick|discovery|vulnerability|full",
    )
    requested_by: Optional[str] = None


class ScanJobOut(BaseModel):
    id: str
    target_ip: str
    scan_type: str
    status: str
    requested_by: Optional[str] = None
    attempts: int
    result_summary: Optional[Dict[str, Any]] = None
    last_error: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class ScanJobListResponse(BaseModel):
    items: List[ScanJobOut]


class NvdImportRequest(BaseModel):
    file_path: str = Field(..., description="Path to local NVD JSON file")
    default_mitigation: str = Field(
        default="Review vendor advisory, apply patches, and validate mitigations.",
        description="Fallback mitigation text when feed has no remediation guidance",
    )


class NvdImportResponse(BaseModel):
    imported_total: int
    created: int
    updated: int
    skipped: int
