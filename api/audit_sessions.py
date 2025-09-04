from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Query, Path, Request, HTTPException, Body, Header, Response

from auth.decorators import ValidatedUser, authorize
from security.endpoint_validator import compute_fingerprint, require_idempotency, store_idempotency, normalize_user_agent, ensure_json_request
from dependencies import AuditSessionServiceDep
from entities.audit_session import (
    AuditSessionCreate,
    AuditSessionFilter,
)
from services.schemas import (
    AuditSessionResponse,
    AuditSessionCreate as SchemaAuditSessionCreate,
)
from common.exceptions import ValidationException, AuthorizationException, BusinessLogicException
from policies.audit_sessions import (
    ALLOWED_FIELDS_CREATE,
)

# --- constants / helpers ---
IDEMPOTENCY_TTL_SECONDS = 24 * 3600

router = APIRouter(prefix="/audit-sessions", tags=["Audit Sessions"])

@router.get("/user/{user_id}",
    summary="Get audit sessions by user ID",
    description="Fetches audit sessions for a specific user with pagination and access control.",
    response_model=List[AuditSessionResponse]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_user_audit_sessions(
    user_id: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    active_only: bool = Query(False, description="Only return active sessions"),
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> List[AuditSessionResponse]:
    """Get audit sessions for a specific user."""
    try:
        # For non-admin users, they can only see their own sessions
        if (getattr(current_user, "role", None) != "admin") and (user_id != current_user.id):
            raise HTTPException(status_code=403, detail="Access denied to user's audit sessions")
        
        # Create filters
        filters = AuditSessionFilter(
            user_id=user_id,
            is_active=active_only if active_only else None
        )
        
        # Get sessions from service
        sessions = await audit_session_service.list_sessions(
            user_id=current_user.id,
            skip=skip,
            limit=limit,
            filters=filters
        )
        
        # Convert to response models
        return [
            AuditSessionResponse(
                id=session.id,
                user_id=session.user_id,
                session_name=session.session_name,
                compliance_domain=session.compliance_domain,
                is_active=session.is_active,
                total_queries=session.total_queries,
                started_at=session.started_at,
                ended_at=session.ended_at,
                session_summary=session.session_summary,
                audit_report=session.audit_report,
                ip_address=session.ip_address,
                user_agent=session.user_agent,
            )
            for session in sessions
        ]
        
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)

@router.get("/{session_id}",
    summary="Get audit session by ID",
    description="Fetches a specific audit session by its ID with access control.",
    response_model=AuditSessionResponse
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_audit_session(
    session_id: str = Path(..., description="Audit session UUID"),
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> AuditSessionResponse:
    """Get audit session by ID."""
    try:
        # Get session from service (includes access control)
        session = await audit_session_service.get_session_by_id(session_id, current_user.id)
        
        # Convert to response model
        return AuditSessionResponse(
            id=session.id,
            user_id=session.user_id,
            session_name=session.session_name,
            compliance_domain=session.compliance_domain,
            is_active=session.is_active,
            total_queries=session.total_queries,
            started_at=session.started_at,
            ended_at=session.ended_at,
            session_summary=session.session_summary,
            audit_report=session.audit_report,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            created_at=session.created_at,
            updated_at=session.updated_at
        )
        
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)

@router.get("/status/{is_active}",
    summary="Get audit sessions by active status",
    description="Fetches audit sessions filtered by active/inactive status.",
    response_model=List[AuditSessionResponse]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_audit_sessions_by_status(
    is_active: bool,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> List[AuditSessionResponse]:
    """Get audit sessions by status."""
    try:
        # Create filters
        filters = AuditSessionFilter(is_active=is_active)
        
        # Get sessions from service
        sessions = await audit_session_service.list_sessions(
            user_id=current_user.id,
            skip=skip,
            limit=limit,
            filters=filters
        )
        
        # Convert to response models
        return [
            AuditSessionResponse(
                id=session.id,
                user_id=session.user_id,
                session_name=session.session_name,
                compliance_domain=session.compliance_domain,
                is_active=session.is_active,
                total_queries=session.total_queries,
                started_at=session.started_at,
                ended_at=session.ended_at,
                session_summary=session.session_summary,
                audit_report=session.audit_report,
                ip_address=session.ip_address,
                user_agent=session.user_agent,
            )
            for session in sessions
        ]
        
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)

@router.get("/domain/{compliance_domain}",
    summary="Get audit sessions by compliance domain",
    description="Fetches audit sessions for a specific compliance domain.",
    response_model=List[AuditSessionResponse]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_audit_sessions_by_compliance_domain(
    compliance_domain: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> List[AuditSessionResponse]:
    """Get audit sessions by compliance domain."""
    try:
        # Create filters
        filters = AuditSessionFilter(compliance_domain=compliance_domain)
        
        # Get sessions from service
        sessions = await audit_session_service.list_sessions(
            user_id=current_user.id,
            skip=skip,
            limit=limit,
            filters=filters
        )
        
        # Convert to response models
        return [
            AuditSessionResponse(
                id=session.id,
                user_id=session.user_id,
                session_name=session.session_name,
                compliance_domain=session.compliance_domain,
                is_active=session.is_active,
                total_queries=session.total_queries,
                started_at=session.started_at,
                ended_at=session.ended_at,
                session_summary=session.session_summary,
                audit_report=session.audit_report,
                ip_address=session.ip_address,
                user_agent=session.user_agent,
            )
            for session in sessions
        ]
        
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)

@router.post("",
    summary="Create new audit session",
    description="Creates a new audit session with the provided details and access control.",
    response_model=Dict[str, Any],
    status_code=201
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def create_new_audit_session(
    request: Request,
    response: Response,
    session_data: SchemaAuditSessionCreate = Body(
        ...,
        description="Audit session creation data"
    ),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", convert_underscores=False),
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    """Create new audit session."""
    # NIST SP 800-53 SI-10: Input validation
    ensure_json_request(request)
    ua = normalize_user_agent(request.headers.get("user-agent"))
    
    try:
        # Extract client information for audit trail
        ip_address = request.client.host if request.client else None
        
        # Convert request data to dict for processing
        if hasattr(session_data, "model_dump"):
            payload = session_data.model_dump()
        elif hasattr(session_data, "dict"):
            payload = session_data.dict()
        else:
            payload = dict(session_data)
        
        # Filter payload to only allowed create fields (OWASP API3:2023)
        payload = {k: v for k, v in payload.items() if k in ALLOWED_FIELDS_CREATE}
        
        # Validate required fields are present
        if not payload.get("session_name") or not payload.get("compliance_domain"):
            raise HTTPException(
                status_code=400,
                detail="session_name and compliance_domain are required"
            )
        
        # Idempotency protection for create operations
        fingerprint = compute_fingerprint(payload | {"user_id": current_user.id})
        repo = request.app.state.idempotency_repo
        cached = require_idempotency(repo, idempotency_key, fingerprint)
        
        if cached:
            response.headers["Location"] = cached.get("location", "")
            return cached["body"]
        
        # Convert to entity with sanitized data
        session_create = AuditSessionCreate(
            user_id=current_user.id,  # Use authenticated user's ID
            session_name=payload["session_name"],
            compliance_domain=payload["compliance_domain"],
            ip_address=ip_address,
            user_agent=ua
        )
        
        # Create session using service
        created_session = await audit_session_service.create_session(
            session_create=session_create,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=ua
        )
        
        # Prepare structured response
        session_response = AuditSessionResponse(
            id=created_session.id,
            user_id=created_session.user_id,
            session_name=created_session.session_name,
            compliance_domain=created_session.compliance_domain,
            is_active=created_session.is_active,
            total_queries=created_session.total_queries,
            started_at=created_session.started_at,
            ended_at=created_session.ended_at,
            session_summary=created_session.session_summary,
            audit_report=created_session.audit_report,
            ip_address=created_session.ip_address,
            user_agent=created_session.user_agent,
            created_at=created_session.created_at,
            updated_at=created_session.updated_at
        )
        
        location = f"/v1/audit-sessions/{created_session.id}"
        body = {"data": session_response.model_dump(), "meta": {"message": "Audit session created"}}
        
        # Store idempotency result
        store_idempotency(repo, idempotency_key, fingerprint, {"body": body, "location": location}, IDEMPOTENCY_TTL_SECONDS)
        
        response.headers["Location"] = location
        return body
        
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)

@router.put("/{session_id}/activate",
    summary="Activate audit session",
    description="Activate a closed audit session.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def activate_audit_session(
    request: Request,
    response: Response,
    session_id: str = Path(..., description="Audit session UUID", regex=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", convert_underscores=False),
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    # No body expected; do not enforce JSON content-type on this route
    ua = normalize_user_agent(request.headers.get("user-agent"))
    
    try:
        ip_address = request.client.host if request.client else None
        
        # Idempotency protection for activation operations
        fingerprint = compute_fingerprint({
            "session_id": session_id,
            "operation": "activate",
            "user_id": current_user.id
        })
        repo = request.app.state.idempotency_repo
        cached = require_idempotency(repo, idempotency_key, fingerprint)
        
        if cached:
            return cached["body"]
        
        opened_session = await audit_session_service.open_session(
            session_id=session_id,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=ua
        )
        
        session_response = AuditSessionResponse(
            id=opened_session.id,
            user_id=opened_session.user_id,
            session_name=opened_session.session_name,
            compliance_domain=opened_session.compliance_domain,
            is_active=opened_session.is_active,
            total_queries=opened_session.total_queries,
            started_at=opened_session.started_at,
            ended_at=opened_session.ended_at,
            session_summary=opened_session.session_summary,
            audit_report=opened_session.audit_report,
            ip_address=opened_session.ip_address,
            user_agent=opened_session.user_agent,
            created_at=opened_session.created_at,
            updated_at=opened_session.updated_at
        )
        
        body = {"data": session_response.model_dump(), "meta": {"message": "Audit session activated", "user_agent": ua}}
        
        # Store idempotency result
        store_idempotency(
            repo, idempotency_key, fingerprint,
            {"body": body}, IDEMPOTENCY_TTL_SECONDS
        )
        
        return body
        
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)

@router.put("/{session_id}/close",
    summary="Close audit session",
    description="Close an active audit session with optional summary.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def close_audit_session(
    request: Request,
    response: Response,
    session_id: str = Path(..., description="Audit session UUID", regex=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    summary: Optional[str] = Body(None, embed=True, description="Session summary"),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", convert_underscores=False),
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    """Close audit session."""
    # NIST SP 800-53 SI-10: Input validation
    ensure_json_request(request)
    ua = normalize_user_agent(request.headers.get("user-agent"))
    
    try:
        # Extract client information for audit trail
        ip_address = request.client.host if request.client else None
        
        # Validate summary if provided
        if summary and not summary.strip():
            raise HTTPException(
                status_code=400,
                detail="summary cannot be empty if provided"
            )
        
        # Idempotency protection for close operations
        fingerprint = compute_fingerprint({
            "session_id": session_id,
            "operation": "close",
            "summary": summary,
            "user_id": current_user.id
        })
        repo = request.app.state.idempotency_repo
        cached = require_idempotency(repo, idempotency_key, fingerprint)
        
        if cached:
            return cached["body"]
        
        # Close session using service
        closed_session = await audit_session_service.close_session(
            session_id=session_id,
            user_id=current_user.id,
            session_summary=summary.strip() if summary else None,
            ip_address=ip_address,
            user_agent=ua
        )
        
        # Convert to response model
        session_response = AuditSessionResponse(
            id=closed_session.id,
            user_id=closed_session.user_id,
            session_name=closed_session.session_name,
            compliance_domain=closed_session.compliance_domain,
            is_active=closed_session.is_active,
            total_queries=closed_session.total_queries,
            started_at=closed_session.started_at,
            ended_at=closed_session.ended_at,
            session_summary=closed_session.session_summary,
            audit_report=closed_session.audit_report,
            ip_address=closed_session.ip_address,
            user_agent=closed_session.user_agent,
            created_at=closed_session.created_at,
            updated_at=closed_session.updated_at
        )
        
        body = {"data": session_response.model_dump(), "meta": {"message": "Audit session closed", "user_agent": ua}}
        
        # Store idempotency result
        store_idempotency(
            repo, idempotency_key, fingerprint,
            {"body": body}, IDEMPOTENCY_TTL_SECONDS
        )
        
        return body
        
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)
