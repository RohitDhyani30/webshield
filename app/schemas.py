"""
Pydantic request/response schemas for the API layer.
"""
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional


class ScanRequest(BaseModel):
    target_url: HttpUrl
    consent_confirmed: bool = Field(
        ...,
        description="Must be true — confirms user owns or has written permission to test this target."
    )
    max_pages: Optional[int] = None
    max_depth: Optional[int] = None


class FindingOut(BaseModel):
    module: str
    title: str
    severity: str
    confidence: str
    url: Optional[str] = None
    parameter: Optional[str] = None
    remediation: Optional[str] = None


class ScanResultOut(BaseModel):
    scan_id: int
    target_url: str
    status: str
    pages_crawled: int
    forms_found: int
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    findings: list[FindingOut] = []
