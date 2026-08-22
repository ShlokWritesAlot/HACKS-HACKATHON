"""
POST /api/v1/intel/extract  – IOC extraction & threat-intel enrichment endpoint.
"""

from __future__ import annotations

from fastapi import APIRouter, status
from pydantic import BaseModel, ConfigDict, Field

from app.intel.extractor import build_threat_report
from app.intel.providers import build_default_registry
from app.intel.schemas import ThreatReport

router = APIRouter()

_registry = build_default_registry()


class IntelExtractRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(..., min_length=1, max_length=5000)


class IntelExtractResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    report: ThreatReport
    enrichment_count: int


@router.post(
    "/extract",
    response_model=IntelExtractResponse,
    status_code=status.HTTP_200_OK,
    summary="Extract and Enrich IOCs from SMS",
    description=(
        "Extracts URLs, domains, IPs, phone numbers, emails, UPI IDs and sender IDs "
        "from an SMS. Runs extracted indicators through configured threat-intel providers. "
        "NEVER fetches user-supplied URLs."
    ),
)
async def extract_indicators(request: IntelExtractRequest) -> IntelExtractResponse:
    report = build_threat_report(request.message)
    enrichments = await _registry.enrich_all(report.indicators)
    report.enrichments = enrichments
    return IntelExtractResponse(report=report, enrichment_count=len(enrichments))
