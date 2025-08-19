from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Query, Path, Request, HTTPException

from auth.decorators import ValidatedUser, authorize
from dependencies import AuditSessionServiceDep
from entities.audit_session import (
    AuditSessionCreate,
    AuditSessionUpdate,
    AuditSessionFilter,
)
from services.schemas import (
    AuditSessionResponse,
    AuditSessionCreate as SchemaAuditSessionCreate,
    AuditSessionUpdate as SchemaAuditSessionUpdate,
    AuditSessionSearchRequest,
)
from common.exceptions import ValidationException, AuthorizationException, BusinessLogicException

router = APIRouter(prefix="/audit-sessions", tags=["Audit Sessions"])


@router.get("",
    summary="List all audit sessions with pagination",
    description="Fetches paginated audit sessions with access control and filtering.",
    response_model=List[AuditSessionResponse]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_all_audit_sessions(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> List[AuditSessionResponse]:
    """List audit sessions with access control."""
    try:
        # Create filters
        filters = AuditSessionFilter(
            compliance_domain=compliance_domain,
            is_active=is_active
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
        if not current_user.is_admin() and user_id != current_user.id:
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


@router.post("/search",
    summary="Search audit sessions",
    description="Search audit sessions using various criteria with access control.",
    response_model=List[AuditSessionResponse]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def search_audit_sessions_endpoint(
    search_request: AuditSessionSearchRequest,
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> List[AuditSessionResponse]:
    """Search audit sessions."""
    try:
        # Search sessions using service
        sessions = await audit_session_service.search_sessions(
            user_id=current_user.id,
            compliance_domain=search_request.compliance_domain,
            is_active=search_request.is_active,
            started_after=search_request.started_after,
            started_before=search_request.started_before,
            session_name_query=getattr(search_request, 'session_name_contains', None),
            skip=search_request.skip,
            limit=search_request.limit
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
    response_model=AuditSessionResponse,
    status_code=201
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def create_new_audit_session(
    session_data: SchemaAuditSessionCreate,
    request: Request,
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> AuditSessionResponse:
    """Create new audit session."""
    try:
        # Extract client information for audit trail
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        
        # Convert schema to entity
        session_create = AuditSessionCreate(
            user_id=current_user.id,  # Use authenticated user's ID
            session_name=session_data.session_name,
            compliance_domain=session_data.compliance_domain,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Create session using service
        created_session = await audit_session_service.create_session(
            session_create=session_create,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Convert to response model
        return AuditSessionResponse(
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
        
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)


@router.patch("/{session_id}",
    summary="Update audit session",
    description="Updates an existing audit session with new information and access control.",
    response_model=AuditSessionResponse
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def update_existing_audit_session(
    session_id: str,
    session_update: SchemaAuditSessionUpdate,
    request: Request,
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> AuditSessionResponse:
    """Update existing audit session."""
    try:
        # Extract client information for audit trail
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        
        # Convert schema to entity
        update_data = AuditSessionUpdate(
            session_name=session_update.session_name,
            session_summary=session_update.session_summary,
            audit_report=session_update.audit_report,
            is_active=session_update.is_active,
            ended_at=session_update.ended_at
        )
        
        # Update session using service
        updated_session = await audit_session_service.update_session(
            session_id=session_id,
            update_data=update_data,
            user_id=current_user.id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Convert to response model
        return AuditSessionResponse(
            id=updated_session.id,
            user_id=updated_session.user_id,
            session_name=updated_session.session_name,
            compliance_domain=updated_session.compliance_domain,
            is_active=updated_session.is_active,
            total_queries=updated_session.total_queries,
            started_at=updated_session.started_at,
            ended_at=updated_session.ended_at,
            session_summary=updated_session.session_summary,
            audit_report=updated_session.audit_report,
            ip_address=updated_session.ip_address,
            user_agent=updated_session.user_agent,
            created_at=updated_session.created_at,
            updated_at=updated_session.updated_at
        )
        
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)


@router.delete("/{session_id}",
    summary="Delete audit session",
    description="Soft delete an audit session (deactivate) or hard delete (admin only).",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def delete_audit_session(
    request: Request,
    session_id: str,
    hard_delete: bool = Query(False, description="Permanently delete (admin only)"),
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    """Delete audit session."""
    try:
        # Extract client information for audit trail
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        
        # Delete session using service
        success = await audit_session_service.delete_session(
            session_id=session_id,
            user_id=current_user.id,
            soft_delete=not hard_delete,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return {
            "success": success,
            "message": f"Audit session {'permanently deleted' if hard_delete else 'deactivated'} successfully",
            "session_id": session_id
        }
        
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)


@router.post("/{session_id}/close",
    summary="Close audit session",
    description="Close an active audit session with optional summary.",
    response_model=AuditSessionResponse
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def close_audit_session(
    request: Request,
    session_id: str,
    summary: Optional[str] = None,
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> AuditSessionResponse:
    """Close audit session."""
    try:
        # Extract client information for audit trail
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        
        # Close session using service
        closed_session = await audit_session_service.close_session(
            session_id=session_id,
            user_id=current_user.id,
            session_summary=summary,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Convert to response model
        return AuditSessionResponse(
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
        
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)


@router.get("/statistics",
    summary="Get audit session statistics",
    description="Get aggregated statistics about audit sessions with access control.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_audit_session_statistics_endpoint(
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    target_user_id: Optional[str] = Query(None, description="Filter by user ID (admin only)"),
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    """Get audit session statistics."""
    try:
        # Get statistics using service
        statistics = await audit_session_service.get_session_statistics(
            user_id=current_user.id,
            compliance_domain=compliance_domain,
            target_user_id=target_user_id
        )
        
        return statistics.model_dump()
        
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)