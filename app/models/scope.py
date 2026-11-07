from datetime import datetime
from typing import Annotated
from pydantic import BaseModel, Field


class ScopeCreate(BaseModel):
    root_domain: str = Field(min_length=3, max_length=253)
    program_name: str = Field(default="", max_length=120)
    authorization_reference: str = Field(default="", max_length=500)
    include_subdomains: bool = True
    included_assets: list[str] = Field(default_factory=list, max_length=100)
    excluded_subdomains: list[str] = Field(default_factory=list, max_length=100)
    local_lab_ports: list[Annotated[int, Field(ge=1, le=65535)]] = Field(default_factory=list, max_length=20)
    authorization_notes: str = Field(min_length=1, max_length=4000)
    authorization_confirmed: bool
    local_lab_mode: bool = False


class ScopeRecord(ScopeCreate):
    id: int
    created_at: datetime
    authorization_status: str = "PENDING"
    authorization_verified_by: str | None = None
    authorization_verified_at: datetime | None = None


class AuthorizationVerification(BaseModel):
    verified: bool
    verified_by: str = Field(min_length=2, max_length=120)
    review_notes: str = Field(min_length=10, max_length=2000)
    authorization_reference: str = Field(default="", max_length=500)


class AuthorizationReviewCreate(BaseModel):
    program_name: str = Field(min_length=1, max_length=120)
    platform_name: str = Field(min_length=1, max_length=120)
    authorized_asset: str = Field(min_length=3, max_length=253)
    allow_subdomains: bool = False
    policy_url: str = Field(min_length=8, max_length=500)
    excluded_assets: list[str] = Field(default_factory=list, max_length=100)
    evidence_notes: str = Field(default="", max_length=4000)
    expires_at: datetime | None = None


class AuthorizationReviewDecision(BaseModel):
    status: str
    reviewer: str = Field(min_length=2, max_length=120)
    decision: str = Field(min_length=3, max_length=2000)


class ScanModeUpdate(BaseModel):
    scan_mode: str
