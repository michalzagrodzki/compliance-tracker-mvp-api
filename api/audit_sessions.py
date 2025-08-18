from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Query, Path

from auth.decorators import ValidatedUser, authorize
from services.audit_sessions import (
    list_audit_sessions,
    get_audit_sessions_by_user,
    get_audit_session_by_id,
    get_audit_sessions_by_active_status,
    get_audit_sessions_by_domain,
    search_audit_sessions,
    create_audit_session,
    update_audit_session,
    get_audit_session_statistics,
)
from services.schemas import (
    AuditSessionResponse,
    AuditSessionCreate,
    AuditSessionUpdate,
    AuditSessionSearchRequest,
)

router = APIRouter(prefix="/audit-sessions", tags=["Audit Sessions"])


@router.get("",
    summary="List all audit sessions with pagination",
    description="Fetches paginated audit sessions from the Supabase 'audit_sessions' table.",
    response_model=List[AuditSessionResponse]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_all_audit_sessions(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
) -> List[AuditSessionResponse]:
    return list_audit_sessions(skip=skip, limit=limit)


@router.get("/user/{user_id}",
    summary="Get audit sessions by user ID",
    description="Fetches audit sessions for a specific user with pagination.",
    response_model=List[AuditSessionResponse]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_user_audit_sessions(
    user_id: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    current_user: ValidatedUser = None
) -> List[AuditSessionResponse]:
    return get_audit_sessions_by_user(user_id, skip, limit)


@router.get("/{session_id}",
    summary="Get audit session by ID",
    description="Fetches a specific audit session by its ID.",
    response_model=AuditSessionResponse
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_session(
    session_id: str = Path(..., description="Audit session UUID"),
) -> AuditSessionResponse:
    return get_audit_session_by_id(session_id)


@router.get("/status/{is_active}",
    summary="Get audit sessions by active status",
    description="Fetches audit sessions filtered by active/inactive status.",
    response_model=List[AuditSessionResponse]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_audit_sessions_by_status(
    is_active: bool,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
) -> List[AuditSessionResponse]:
    return get_audit_sessions_by_active_status(is_active, skip, limit)


@router.get("/domain/{compliance_domain}",
    summary="Get audit sessions by compliance domain",
    description="Fetches audit sessions for a specific compliance domain.",
    response_model=List[AuditSessionResponse]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_sessions_by_compliance_domain(
    compliance_domain: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
) -> List[AuditSessionResponse]:
    return get_audit_sessions_by_domain(compliance_domain, skip, limit)


@router.post("/search",
    summary="Search audit sessions",
    description="Search audit sessions using various criteria.",
    response_model=List[AuditSessionResponse]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def search_audit_sessions_endpoint(
    search_request: AuditSessionSearchRequest,
    current_user: ValidatedUser = None
) -> List[AuditSessionResponse]:
    return search_audit_sessions(search_request, current_user)


@router.post("",
    summary="Create new audit session",
    description="Creates a new audit session with the provided details.",
    response_model=Dict[str, Any],
    status_code=201
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def create_new_audit_session(
    session_data: AuditSessionCreate,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return create_audit_session(session_data, current_user.id)


@router.patch("/{session_id}",
    summary="Update audit session",
    description="Updates an existing audit session with new information.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def update_existing_audit_session(
    session_id: str,
    session_update: AuditSessionUpdate,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return update_audit_session(session_id, session_update, current_user.id)


@router.get("/statistics",
    summary="Get audit session statistics",
    description="Get aggregated statistics about audit sessions.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_session_statistics_endpoint(
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return get_audit_session_statistics(compliance_domain, current_user)