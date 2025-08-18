from typing import Any, List, Dict, Optional, Union
from fastapi import APIRouter, Query, Path, Body, Request, HTTPException
import logging

from auth.decorators import ValidatedUser, authorize
from services.compliance_domain import get_compliance_domain_by_code, list_compliance_domains
from services.compliance_gaps import (
    list_compliance_gaps,
    list_compliance_gaps_by_compliance_domains,
    get_compliance_gap_by_id,
    create_compliance_gap,
    update_compliance_gap,
    update_gap_status,
    assign_gap_to_user,
    mark_gap_reviewed,
    get_gaps_by_domain,
    get_gaps_by_user,
    get_gaps_by_audit_session,
    get_compliance_gaps_statistics,
)
from services.compliance_gap_recommendation import generate_compliance_recommendation
from services.schemas import (
    ComplianceDomain,
    ComplianceGapCreate,
    ComplianceGapFromChatHistoryRequest,
    ComplianceGapUpdate,
    ComplianceGapStatusUpdate,
    ComplianceRecommendationRequest,
    ComplianceRecommendationResponse,
)

router = APIRouter(tags=["Compliance"])


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


@router.get("/compliance-gaps",
    summary="List compliance gaps with filtering",
    description="Get paginated compliance gaps with optional filtering by domain, type, risk level, etc.",
    response_model=List[Dict[str, Any]],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_all_compliance_gaps(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    gap_type: Optional[str] = Query(None, description="Filter by gap type"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    status: Optional[str] = Query(None, description="Filter by status"),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned user"),
    user_id: Optional[str] = Query(None, description="Filter by creator user"),
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session"),
    detection_method: Optional[str] = Query(None, description="Filter by detection method"),
    regulatory_requirement: Optional[bool] = Query(None, description="Filter by regulatory requirement status"),
) -> List[Dict[str, Any]]:
    return list_compliance_gaps(
        skip=skip,
        limit=limit,
        compliance_domain=compliance_domain,
        gap_type=gap_type,
        risk_level=risk_level,
        status=status,
        assigned_to=assigned_to,
        user_id=user_id,
        audit_session_id=audit_session_id,
        detection_method=detection_method,
        regulatory_requirement=regulatory_requirement
    )


@router.get("/compliance-gaps/compliance-domains",
    summary="List compliance gaps by compliance domains linked to user",
    description="List all compliance gaps by compliance domains linked to user",
    response_model=List[Dict[str, Any]],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_compliance_gaps_by_compliance_domains(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    current_user: ValidatedUser = None
) -> List[Dict[str, Any]]:
    user_compliance_domains = getattr(current_user, 'compliance_domains', [])
    
    if not user_compliance_domains:
        raise HTTPException(
            status_code=403,
            detail="Access denied."
        )
    return list_compliance_gaps_by_compliance_domains(user_compliance_domains, skip, limit)


@router.get("/compliance-gaps/{gap_id}",
    summary="Get compliance gap by ID",
    description="Get detailed information about a specific compliance gap",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_compliance_gap(
    gap_id: str = Path(..., description="Compliance gap UUID"),
) -> Dict[str, Any]:
    return get_compliance_gap_by_id(gap_id)


@router.post("/compliance-gaps",
    summary="Create new compliance gap",
    description="Create a new compliance gap record from manual input or existing chat history",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"],
    status_code=201
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def create_new_compliance_gap(
    request: Request,
    request_data: Union[ComplianceGapCreate, ComplianceGapFromChatHistoryRequest] = Body(
        ...,
        discriminator="creation_method",
        description="Either a complete gap definition or a reference to chat history"
    ),
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    # This is a simplified version - the full logic from the original should be implemented
    return create_compliance_gap(
        gap_data=request_data,
        user_id=current_user.id,
        ip_address=ip_address,
        user_agent=user_agent
    )


@router.patch("/compliance-gaps/{gap_id}",
    summary="Update compliance gap",
    description="Update an existing compliance gap with new information",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def update_existing_compliance_gap(
    gap_id: str,
    gap_update: ComplianceGapUpdate,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return update_compliance_gap(
        gap_id=gap_id,
        gap_data=gap_update,
        user_id=current_user.id
    )


@router.put("/compliance-gaps/{gap_id}/status",
    summary="Update compliance gap status",
    description="Update the status of a compliance gap",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def update_compliance_gap_status(
    gap_id: str,
    status_update: ComplianceGapStatusUpdate,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return update_gap_status(
        gap_id=gap_id,
        status=status_update.status,
        user_id=current_user.id
    )


@router.put("/compliance-gaps/{gap_id}/assign",
    summary="Assign compliance gap",
    description="Assign a compliance gap to a user",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def assign_compliance_gap(
    gap_id: str,
    assigned_user_id: str = Body(..., embed=True),
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return assign_gap_to_user(
        gap_id=gap_id,
        assigned_user_id=assigned_user_id,
        assigner_user_id=current_user.id
    )


@router.put("/compliance-gaps/{gap_id}/review",
    summary="Mark compliance gap as reviewed",
    description="Mark a compliance gap as reviewed by the current user",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def review_compliance_gap(
    gap_id: str,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return mark_gap_reviewed(
        gap_id=gap_id,
        reviewer_user_id=current_user.id
    )


@router.post("/compliance-gaps/recommendation",
    response_model=ComplianceRecommendationResponse,
    summary="Generate compliance gap recommendation",
    description="Generate AI-powered recommendations for addressing a compliance gap",
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def create_compliance_recommendation(
    request: ComplianceRecommendationRequest,
    current_user: ValidatedUser = None
) -> ComplianceRecommendationResponse:
    return generate_compliance_recommendation(
        gap_id=request.gap_id,
        compliance_domain=request.compliance_domain,
        user_id=current_user.id
    )


@router.get("/compliance-domains/{domain_code}/gaps",
    summary="Get compliance gaps by domain",
    description="Get all compliance gaps for a specific compliance domain",
    response_model=List[Dict[str, Any]],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_domain_compliance_gaps(
    domain_code: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    current_user: ValidatedUser = None
) -> List[Dict[str, Any]]:
    user_compliance_domains = getattr(current_user, 'compliance_domains', [])
    
    if domain_code not in user_compliance_domains:
        raise HTTPException(
            status_code=403,
            detail="Access denied to this compliance domain."
        )
    
    return get_gaps_by_domain(domain_code, skip, limit)


@router.get("/users/{user_id}/gaps",
    summary="Get compliance gaps by user",
    description="Get all compliance gaps assigned to or created by a specific user",
    response_model=List[Dict[str, Any]],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_user_compliance_gaps(
    user_id: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
) -> List[Dict[str, Any]]:
    return get_gaps_by_user(user_id, skip, limit)


@router.get("/audit-sessions/{audit_session_id}/gaps",
    summary="Get compliance gaps by audit session",
    description="Get all compliance gaps associated with a specific audit session",
    response_model=List[Dict[str, Any]],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_session_compliance_gaps(
    audit_session_id: str,
) -> List[Dict[str, Any]]:
    return get_gaps_by_audit_session(audit_session_id)


@router.get("/compliance-gaps/statistics",
    summary="Get compliance gaps statistics",
    description="Get aggregated statistics about compliance gaps",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_compliance_gap_statistics(
    compliance_domain: Optional[str] = Query(None, description="Filter statistics by compliance domain"),
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    if compliance_domain:
        user_compliance_domains = getattr(current_user, 'compliance_domains', [])
        if compliance_domain not in user_compliance_domains:
            raise HTTPException(
                status_code=403,
                detail="Access denied to this compliance domain."
            )
    
    return get_compliance_gaps_statistics(compliance_domain)