from typing import List, Optional
from fastapi import APIRouter, Query, Path, Body, Request, HTTPException, Depends

from auth.decorators import authorize
from services.compliance_domain import get_compliance_domain_by_code, list_compliance_domains

from services.schemas import (
    ComplianceDomain
)

router = APIRouter(tags=["Compliance Domains"])


@router.get("/compliance-domains",
    summary="List compliance domains with pagination",
    description="Fetches paginated rows from the Supabase 'compliance_domains' table.",
    response_model=List[ComplianceDomain]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_compliance_domains(
    skip: Optional[int] = Query(0, ge=0, description="Number of domains to skip for pagination"),
    limit: Optional[int] = Query(10, ge=1, le=100, description="Maximum number of domains to return"),
    is_active: Optional[bool] = Query(None, description="Filter by active status. If None, returns all domains"),
) -> List[ComplianceDomain]:
    return list_compliance_domains(skip=skip or 0, limit=limit or 10, is_active=is_active)


@router.get("/compliance-domains/{code}",
    summary="Get compliance domain by code",
    description="Fetches a specific compliance domain by its unique code.",
    response_model=ComplianceDomain
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_compliance_domain(
    code: str,
) -> ComplianceDomain:
    return get_compliance_domain_by_code(code)