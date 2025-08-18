from typing import Any, List, Dict
from fastapi import APIRouter, Query, Path, HTTPException

from auth.decorators import ValidatedUser, authorize
from services.audit_log import (
    list_audit_logs,
    get_audit_log_by_id,
    list_audit_logs_by_user,
    list_audit_logs_by_audit_session,
    list_audit_logs_by_compliance_domain,
    list_audit_logs_by_object,
    list_audit_logs_filtered,
)

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])


@router.get("",
    summary="List audit logs with pagination",
    description="Fetches paginated audit logs from the database.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_all_audit_logs(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
) -> List[Dict[str, Any]]:
    return list_audit_logs(skip=skip, limit=limit)


@router.get("/{log_id}",
    summary="Get audit log by ID",
    description="Fetches a specific audit log entry by its ID.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_audit_log(
    log_id: str = Path(..., description="Audit log UUID"),
) -> Dict[str, Any]:
    return get_audit_log_by_id(log_id)


@router.get("/user/{user_id}",
    summary="List audit logs by user ID",
    description="Fetches audit logs for a specific user.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_audit_logs_by_user(
    user_id: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
) -> List[Dict[str, Any]]:
    return list_audit_logs_by_user(user_id, skip, limit)


@router.get("/object/{object_type}/{object_id}",
    summary="List audit logs by object",
    description="Fetches audit logs for a specific object type and ID.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_audit_logs_by_object(
    object_type: str,
    object_id: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
) -> List[Dict[str, Any]]:
    return list_audit_logs_by_object(object_type, object_id, skip, limit)


@router.get("/audit-session/{audit_session_id}",
    summary="List audit logs by audit session ID",
    description="Fetches audit logs for a specific audit session.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_logs_by_audit_session(
    audit_session_id: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
) -> List[Dict[str, Any]]:
    return list_audit_logs_by_audit_session(audit_session_id, skip, limit)


@router.get("/compliance-domain/{compliance_domain_name}",
    summary="List audit logs by compliance domain name",
    description="Fetches audit logs for a specific compliance domain.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_logs_by_compliance_domain(
    compliance_domain_name: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    current_user: ValidatedUser = None
) -> List[Dict[str, Any]]:
    user_compliance_domains = getattr(current_user, 'compliance_domains', [])
    
    if compliance_domain_name not in user_compliance_domains:
        raise HTTPException(
            status_code=403,
            detail="Access denied to this compliance domain."
        )
    
    return list_audit_logs_by_compliance_domain(compliance_domain_name, skip, limit)


@router.get("/filtered",
    summary="Get filtered audit logs",
    description="Get audit logs with advanced filtering options.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_filtered_audit_logs(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    object_type: str = Query(None, description="Filter by object type"),
    action: str = Query(None, description="Filter by action"),
    user_id: str = Query(None, description="Filter by user ID"),
    audit_session_id: str = Query(None, description="Filter by audit session ID"),
    compliance_domain: str = Query(None, description="Filter by compliance domain"),
    risk_level: str = Query(None, description="Filter by risk level"),
    start_date: str = Query(None, description="Filter by start date (ISO format)"),
    end_date: str = Query(None, description="Filter by end date (ISO format)"),
) -> List[Dict[str, Any]]:
    filters = {}
    if object_type:
        filters['object_type'] = object_type
    if action:
        filters['action'] = action
    if user_id:
        filters['user_id'] = user_id
    if audit_session_id:
        filters['audit_session_id'] = audit_session_id
    if compliance_domain:
        filters['compliance_domain'] = compliance_domain
    if risk_level:
        filters['risk_level'] = risk_level
    if start_date:
        filters['start_date'] = start_date
    if end_date:
        filters['end_date'] = end_date
    
    return list_audit_logs_filtered(skip, limit, filters)