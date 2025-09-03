from typing import Any, List, Dict, Optional, Union
from fastapi import APIRouter, Header, Query, Path, Body, Request, HTTPException, Depends, Response
from slowapi import Limiter
from slowapi.util import get_remote_address

from auth.decorators import ValidatedUser, authorize
from policies.compliance_gaps import ALLOWED_FIELDS_CREATE_DIRECT, ALLOWED_FIELDS_CREATE_FROM_CHAT, ALLOWED_FIELDS_UPDATE
from security.endpoint_validator import compute_fingerprint, require_idempotency, store_idempotency, normalize_user_agent, ensure_json_request
from dependencies import (
    get_compliance_recommendation_service,
    get_compliance_gap_repository,
    ComplianceGapServiceDep,
)
from services.schemas import (
    ComplianceGapCreate,
    ComplianceGapFromChatHistoryRequest,
    ComplianceGapUpdate,
    ComplianceGapStatusUpdate,
    ComplianceRecommendationRequest,
    ComplianceRecommendationResponse,
)

# --- constants / helpers ---
IDEMPOTENCY_TTL_SECONDS = 24 * 3600

router = APIRouter(tags=["Compliance Gaps"])
limiter = Limiter(key_func=get_remote_address)

@router.get("/compliance-gaps",
    summary="List compliance gaps with filtering",
    description="Get paginated compliance gaps with optional filtering by domain, type, risk level, etc.",
    response_model=List[Dict[str, Any]],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_all_compliance_gaps(
    service: ComplianceGapServiceDep,
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
    current_user: ValidatedUser = None,
) -> List[Dict[str, Any]]:
    gaps = await service.list_compliance_gaps(
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
        regulatory_requirement=regulatory_requirement,
    )
    return [g.model_dump() if hasattr(g, "model_dump") else dict(g) for g in gaps]

@router.get("/compliance-gaps/compliance-domains",
    summary="List compliance gaps by compliance domains linked to user",
    description="List all compliance gaps by compliance domains linked to user",
    response_model=List[Dict[str, Any]],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_compliance_gaps_by_compliance_domains(
    service: ComplianceGapServiceDep,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    current_user: ValidatedUser = None,
) -> List[Dict[str, Any]]:
    user_compliance_domains = getattr(current_user, 'compliance_domains', [])
    
    if not user_compliance_domains:
        raise HTTPException(
            status_code=403,
            detail="Access denied."
        )
    gaps = await service.list_compliance_gaps_by_compliance_domains(user_compliance_domains, skip, limit)
    return [g.model_dump() if hasattr(g, "model_dump") else dict(g) for g in gaps]

@router.get("/compliance-gaps/{gap_id}",
    summary="Get compliance gap by ID",
    description="Get detailed information about a specific compliance gap",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_compliance_gap(
    service: ComplianceGapServiceDep,
    gap_id: str = Path(..., description="Compliance gap UUID"),
) -> Dict[str, Any]:
    gap = await service.get_compliance_gap_by_id(gap_id)
    return gap.model_dump() if hasattr(gap, "model_dump") else dict(gap)

@router.post("/compliance-gaps",
    summary="Create new compliance gap",
    description="Create a new compliance gap record from manual input or existing chat history",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"],
    status_code=201
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def create_new_compliance_gap(
    service: ComplianceGapServiceDep,
    request: Request,
    response: Response,
    request_data: Union[ComplianceGapCreate, ComplianceGapFromChatHistoryRequest] = Body(
        ...,
        discriminator="creation_method",
        description="Either a complete gap definition or a reference to chat history"
    ),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", convert_underscores=False),
    current_user: ValidatedUser = None,
) -> Dict[str, Any]:
    ensure_json_request(request)
    ua = normalize_user_agent(request.headers.get("user-agent"))

    # Convert request data to dict for processing
    if hasattr(request_data, "model_dump"):
        payload = request_data.model_dump()
    elif hasattr(request_data, "dict"):
        payload = request_data.dict()
    else:
        payload = dict(request_data)

    allowed = (ALLOWED_FIELDS_CREATE_FROM_CHAT if payload.get("creation_method") == "from_chat_history"
           else ALLOWED_FIELDS_CREATE_DIRECT)
    
    payload = {k: v for k, v in payload.items() if k in allowed}
    fingerprint = compute_fingerprint(payload)
    repo = request.app.state.idempotency_repo
    cached = require_idempotency(repo, idempotency_key, fingerprint)

    if cached:
        response.headers["Location"] = cached.get("location", "")
        return cached["body"]
    
    created_gap = await service.create_compliance_gap(payload | {"user_agent": ua})
    created = created_gap.model_dump() if hasattr(created_gap, "model_dump") else dict(created_gap)
    location = f"/v1/compliance-gaps/{created['id']}"
    body = {"data": created, "meta": {"message": "Compliance gap created"}}

    store_idempotency(repo, idempotency_key, fingerprint, {"body": body, "location": location}, IDEMPOTENCY_TTL_SECONDS)

    response.headers["Location"] = location
    return body

@router.patch("/compliance-gaps/{gap_id}",
    summary="Update compliance gap",
    description="Update an existing compliance gap with new information",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def update_existing_compliance_gap(
    service: ComplianceGapServiceDep,
    request: Request,
    response: Response,
    gap_id: str = Path(..., description="Compliance gap UUID", regex=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    gap_update: ComplianceGapUpdate = Body(..., description="Gap update data"),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", convert_underscores=False),
    current_user: ValidatedUser = None,
) -> Dict[str, Any]:
    # NIST SP 800-53 SI-10: Input validation
    ensure_json_request(request)
    ua = normalize_user_agent(request.headers.get("user-agent"))
    
    # Convert and filter payload to allowed fields only (OWASP API3:2023)
    if hasattr(gap_update, "model_dump"):
        payload = gap_update.model_dump(exclude_unset=True)
    elif hasattr(gap_update, "dict"):
        payload = gap_update.dict(exclude_unset=True)
    else:
        payload = dict(gap_update)
    
    # Filter payload to only allowed update fields
    filtered_payload = {k: v for k, v in payload.items() if k in ALLOWED_FIELDS_UPDATE}
    
    if not filtered_payload:
        raise HTTPException(
            status_code=400,
            detail="No valid update fields provided"
        )
    
    # Idempotency protection for update operations
    fingerprint = compute_fingerprint({"gap_id": gap_id, **filtered_payload})
    repo = request.app.state.idempotency_repo
    cached = require_idempotency(repo, idempotency_key, fingerprint)
    
    if cached:
        return cached["body"]
    
    # Perform update with filtered data
    updated_gap = await service.update_compliance_gap(
        gap_id=gap_id,
        update_data=filtered_payload | {"user_agent": ua},
    )
    updated = updated_gap.model_dump() if hasattr(updated_gap, "model_dump") else dict(updated_gap)
    body = {"data": updated, "meta": {"message": "Compliance gap updated"}}
    
    # Store idempotency result
    store_idempotency(
        repo, idempotency_key, fingerprint, 
        {"body": body}, IDEMPOTENCY_TTL_SECONDS
    )
    
    return body

@router.put("/compliance-gaps/{gap_id}/status",
    summary="Update compliance gap status",
    description="Update the status of a compliance gap",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def update_compliance_gap_status(
    service: ComplianceGapServiceDep,
    request: Request,
    response: Response,
    gap_id: str = Path(..., description="Compliance gap UUID", regex=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    status_update: ComplianceGapStatusUpdate = Body(..., description="Status update data"),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", convert_underscores=False),
    current_user: ValidatedUser = None,
) -> Dict[str, Any]:
    # NIST SP 800-53 SI-10: Input validation
    ensure_json_request(request)
    ua = normalize_user_agent(request.headers.get("user-agent"))
    
    # Extract status and resolution_notes with validation
    if hasattr(status_update, "model_dump"):
        payload = status_update.model_dump()
    elif hasattr(status_update, "dict"):
        payload = status_update.dict()
    else:
        payload = dict(status_update)
    
    # Idempotency protection for status updates
    fingerprint = compute_fingerprint({"gap_id": gap_id, "operation": "status_update", **payload})
    repo = request.app.state.idempotency_repo
    cached = require_idempotency(repo, idempotency_key, fingerprint)
    
    if cached:
        return cached["body"]
    
    # Perform status update
    updated_gap = await service.update_gap_status(
        gap_id=gap_id,
        new_status=status_update.status,
        resolution_notes=status_update.resolution_notes,
    )
    updated = updated_gap.model_dump() if hasattr(updated_gap, "model_dump") else dict(updated_gap)
    body = {"data": updated, "meta": {"message": "Compliance gap status updated", "user_agent": ua}}
    
    # Store idempotency result
    store_idempotency(
        repo, idempotency_key, fingerprint, 
        {"body": body}, IDEMPOTENCY_TTL_SECONDS
    )
    
    return body

@router.put("/compliance-gaps/{gap_id}/review",
    summary="Mark compliance gap as reviewed",
    description="Mark a compliance gap as reviewed by the current user",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def review_compliance_gap(
    service: ComplianceGapServiceDep,
    request: Request,
    response: Response,
    gap_id: str = Path(..., description="Compliance gap UUID", regex=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", convert_underscores=False),
    current_user: ValidatedUser = None,
) -> Dict[str, Any]:
    # NIST SP 800-53 SI-10: Input validation
    ensure_json_request(request)
    ua = normalize_user_agent(request.headers.get("user-agent"))
    
    # Idempotency protection for review operations
    fingerprint = compute_fingerprint({
        "gap_id": gap_id, 
        "operation": "review", 
        "reviewer_id": current_user.id if current_user else None
    })
    repo = request.app.state.idempotency_repo
    cached = require_idempotency(repo, idempotency_key, fingerprint)
    
    if cached:
        return cached["body"]
    
    # Perform review marking
    updated_gap = await service.mark_gap_reviewed(gap_id=gap_id)
    updated = updated_gap.model_dump() if hasattr(updated_gap, "model_dump") else dict(updated_gap)
    body = {"data": updated, "meta": {"message": "Compliance gap marked as reviewed", "user_agent": ua}}
    
    # Store idempotency result
    store_idempotency(
        repo, idempotency_key, fingerprint, 
        {"body": body}, IDEMPOTENCY_TTL_SECONDS
    )
    
    return body

@router.get("/audit-sessions/{audit_session_id}/gaps",
    summary="Get compliance gaps by audit session",
    description="Get all compliance gaps associated with a specific audit session",
    response_model=List[Dict[str, Any]],
    tags=["Compliance Gaps"]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_audit_session_compliance_gaps(
    audit_session_id: str,
    service: ComplianceGapServiceDep,
) -> List[Dict[str, Any]]:
    gaps = await service.get_gaps_by_audit_session(audit_session_id)
    return [g.model_dump() if hasattr(g, "model_dump") else dict(g) for g in gaps]

@router.post("/compliance-gaps/recommendation",
    response_model=ComplianceRecommendationResponse,
    summary="Generate compliance gap recommendation",
    description="Generate AI-powered recommendations for addressing a compliance gap",
    tags=["Compliance Gaps"]
)
@limiter.limit("10/minute")
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def create_compliance_recommendation(
    request_data: ComplianceRecommendationRequest,
    request: Request,
    current_user: ValidatedUser = None,
    recommendation_service = Depends(get_compliance_recommendation_service)
) -> ComplianceRecommendationResponse:
    if getattr(request_data, "gap_id", None):
        gap_repo = get_compliance_gap_repository()
        gap = await gap_repo.get_by_id(request_data.gap_id)

        if not gap:
            raise HTTPException(status_code=404, detail="Compliance gap not found")

        recommendation_data = await recommendation_service.generate_gap_recommendation(
            gap_id=request_data.gap_id,
            user_id=current_user.id,
            recommendation_type="comprehensive",
            include_implementation_plan=True,
        )

        return ComplianceRecommendationResponse(
            recommendation_text=recommendation_data.get("recommendation_text", ""),
            recommendation_type="comprehensive",
            chat_history_id=getattr(gap, "chat_history_id", 0) or 0,
            audit_session_id=str(gap.audit_session_id),
            compliance_domain=str(gap.compliance_domain),
            generation_metadata={
                "gap_id": request_data.gap_id,
                "priority_level": recommendation_data.get("priority_level", "medium"),
                "estimated_effort": recommendation_data.get("total_estimated_effort", "unknown"),
                "implementation_phases": recommendation_data.get("implementation_phases", []),
                "root_cause_analysis": recommendation_data.get("root_cause_analysis", ""),
                "remediation_actions": recommendation_data.get("remediation_actions", []),
                "service_version": "repository_pattern_v1",
            },
        )

    chat = request_data.chat_history_item
    try:
        chat_id_int = int(chat.id) if chat and getattr(chat, "id", None) else 0
    except Exception:
        chat_id_int = 0

    return ComplianceRecommendationResponse(
        recommendation_text="",
        recommendation_type="comprehensive",
        chat_history_id=chat_id_int,
        audit_session_id=str(getattr(chat, "audit_session_id", "") or ""),
        compliance_domain=str(getattr(chat, "compliance_domain", "") or ""),
        generation_metadata={
            "gap_id": None,
            "priority_level": "medium",
            "estimated_effort": "unknown",
            "implementation_phases": [],
            "root_cause_analysis": "",
            "remediation_actions": [],
            "service_version": "repository_pattern_v1",
            "note": "No gap_id provided; returning empty recommendation"
        },
    )
