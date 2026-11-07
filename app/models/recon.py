from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class SubdomainScanStart(BaseModel):
    scope_id: int = Field(gt=0)


class SubdomainAsset(BaseModel):
    hostname: str
    source: str | None = None
    simulated: bool = False
    discovered_at: datetime


class ReconScan(BaseModel):
    id: int
    scope_id: int
    module: str
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    stage: str
    progress: int
    simulated: bool
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    results: list[SubdomainAsset] = Field(default_factory=list)


class SubdomainScanList(BaseModel):
    scans: list[ReconScan]
    results: list[SubdomainAsset]
    tool: dict


class LiveHostScanStart(BaseModel):
    scope_id: int = Field(gt=0)
    target_url: str | None = Field(default=None, min_length=8, max_length=2048)


class LiveHostResult(BaseModel):
    hostname: str
    url: str
    status_code: int | None = None
    title: str | None = None
    content_type: str | None = None
    ip_address: str | None = None
    simulated: bool = False
    discovered_at: datetime


class LiveHostScan(BaseModel):
    id: int
    scope_id: int
    module: Literal["live_hosts"]
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    stage: str
    progress: int
    simulated: bool
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    results: list[LiveHostResult] = Field(default_factory=list)


class URLScanStart(BaseModel):
    scope_id: int = Field(gt=0)


class HistoricalURL(BaseModel):
    url: str
    sources: list[str] = Field(default_factory=list)
    simulated: bool = False
    discovered_at: datetime


class URLScan(BaseModel):
    id: int
    scope_id: int
    module: Literal["urls"]
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    stage: str
    progress: int
    simulated: bool
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    results: list[HistoricalURL] = Field(default_factory=list)


class EndpointScanStart(BaseModel):
    scope_id: int = Field(gt=0)
    target_host: str = Field(min_length=3, max_length=253)
    approval_confirmed: bool


class DiscoveredEndpoint(BaseModel):
    url: str
    method: str = "GET"
    source: str | None = None
    simulated: bool = False
    discovered_at: datetime


class EndpointScan(BaseModel):
    id: int
    scope_id: int
    module: Literal["endpoints"]
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    stage: str
    progress: int
    simulated: bool
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    results: list[DiscoveredEndpoint] = Field(default_factory=list)


class TechnologyScanStart(BaseModel):
    scope_id: int = Field(gt=0)
    target_host: str | None = Field(default=None, min_length=3, max_length=253)


class TechnologyResult(BaseModel):
    hostname: str
    technology: str
    version: str | None = None
    simulated: bool = False
    detected_at: datetime


class TechnologyScan(BaseModel):
    id: int
    scope_id: int
    module: Literal["technologies"]
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    stage: str
    progress: int
    simulated: bool
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    results: list[TechnologyResult] = Field(default_factory=list)


class ReconOrchestrationStart(BaseModel):
    scope_id: int = Field(gt=0)
    active_crawl_approved: bool = False


class ReconStage(BaseModel):
    name: str
    status: Literal["queued", "running", "completed", "skipped", "failed", "cancelled"]
    child_scan_id: int | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ReconOrchestration(BaseModel):
    id: int
    scope_id: int
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    stage: str
    progress: int
    simulated: bool
    active_crawl_approved: bool
    current_child_module: str | None = None
    current_child_scan_id: int | None = None
    error: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    stages: list[ReconStage] = Field(default_factory=list)
