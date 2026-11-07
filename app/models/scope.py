from datetime import datetime
from pydantic import BaseModel, Field


class ScopeCreate(BaseModel):
    root_domain: str = Field(min_length=3, max_length=253)
    program_name: str = Field(default="", max_length=120)
    include_subdomains: bool = True
    included_assets: list[str] = Field(default_factory=list, max_length=100)
    excluded_subdomains: list[str] = Field(default_factory=list, max_length=100)
    authorization_notes: str = Field(min_length=1, max_length=4000)
    authorization_confirmed: bool
    local_lab_mode: bool = False


class ScopeRecord(ScopeCreate):
    id: int
    created_at: datetime
