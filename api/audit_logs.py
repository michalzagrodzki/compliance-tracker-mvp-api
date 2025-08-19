from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Query, Path, HTTPException

from auth.decorators import ValidatedUser, authorize
from dependencies import AuditLogServiceDep
from entities.audit_log import AuditLogFilter
from common.exceptions import (
    ValidationException,
    ResourceNotFoundException,
    BusinessLogicException,
    AuthorizationException
)
from common.logging import get_logger

router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])
logger = get_logger("audit_logs_api")


@router.get("",
    summary="List audit logs with pagination",
    description="Fetches paginated audit logs from the database.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
async def get_all_audit_logs(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    current_user: ValidatedUser = None,
    audit_log_service: AuditLogServiceDep = None
) -> List[Dict[str, Any]]:
    try:
        logs = await audit_log_service.list_audit_logs(
            user_id=current_user.id,
            skip=skip,
            limit=limit
        )
        return [log.to_dict() for log in logs]
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to list audit logs: {e}")
        raise HTTPException(status_code=400 if isinstance(e, ValidationException) else 403, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error listing audit logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error listing audit logs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{log_id}",
    summary="Get audit log by ID",
    description="Fetches a specific audit log entry by its ID.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin"], check_active=True)
async def get_audit_log(
    log_id: str = Path(..., description="Audit log UUID"),
    current_user: ValidatedUser = None,
    audit_log_service: AuditLogServiceDep = None
) -> Dict[str, Any]:
    try:
        log = await audit_log_service.get_audit_log_by_id(log_id, current_user.id)
        return log.to_dict()
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to get audit log {log_id}: {e}")
        raise HTTPException(status_code=400 if isinstance(e, ValidationException) else 403, detail=str(e))
    except ResourceNotFoundException as e:
        logger.error(f"Audit log {log_id} not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error getting audit log {log_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error getting audit log {log_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/user/{user_id}",
    summary="List audit logs by user ID",
    description="Fetches audit logs for a specific user.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
async def get_audit_logs_by_user(
    user_id: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    current_user: ValidatedUser = None,
    audit_log_service: AuditLogServiceDep = None
) -> List[Dict[str, Any]]:
    try:
        logs = await audit_log_service.get_audit_logs_by_user(user_id, current_user.id, skip, limit)
        return [log.to_dict() for log in logs]
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to get audit logs by user {user_id}: {e}")
        raise HTTPException(status_code=400 if isinstance(e, ValidationException) else 403, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error getting audit logs by user {user_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error getting audit logs by user {user_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/object/{object_type}/{object_id}",
    summary="List audit logs by object",
    description="Fetches audit logs for a specific object type and ID.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
async def get_audit_logs_by_object(
    object_type: str,
    object_id: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    current_user: ValidatedUser = None,
    audit_log_service: AuditLogServiceDep = None
) -> List[Dict[str, Any]]:
    try:
        logs = await audit_log_service.get_audit_logs_by_object(object_type, object_id, current_user.id, skip, limit)
        return [log.to_dict() for log in logs]
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to get audit logs by object {object_type}/{object_id}: {e}")
        raise HTTPException(status_code=400 if isinstance(e, ValidationException) else 403, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error getting audit logs by object {object_type}/{object_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error getting audit logs by object {object_type}/{object_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/audit-session/{audit_session_id}",
    summary="List audit logs by audit session ID",
    description="Fetches audit logs for a specific audit session.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_audit_logs_by_audit_session(
    audit_session_id: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    current_user: ValidatedUser = None,
    audit_log_service: AuditLogServiceDep = None
) -> List[Dict[str, Any]]:
    try:
        logs = await audit_log_service.get_audit_logs_by_audit_session(audit_session_id, current_user.id, skip, limit)
        return [log.to_dict() for log in logs]
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to get audit logs by audit session {audit_session_id}: {e}")
        raise HTTPException(status_code=400 if isinstance(e, ValidationException) else 403, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error getting audit logs by audit session {audit_session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error getting audit logs by audit session {audit_session_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/compliance-domain/{compliance_domain_name}",
    summary="List audit logs by compliance domain name",
    description="Fetches audit logs for a specific compliance domain.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_audit_logs_by_compliance_domain(
    compliance_domain_name: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    current_user: ValidatedUser = None,
    audit_log_service: AuditLogServiceDep = None
) -> List[Dict[str, Any]]:
    try:
        logs = await audit_log_service.get_audit_logs_by_compliance_domain(compliance_domain_name, current_user.id, skip, limit)
        return [log.to_dict() for log in logs]
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to get audit logs by domain {compliance_domain_name}: {e}")
        raise HTTPException(status_code=400 if isinstance(e, ValidationException) else 403, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error getting audit logs by domain {compliance_domain_name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error getting audit logs by domain {compliance_domain_name}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/filtered",
    summary="Get filtered audit logs",
    description="Get audit logs with advanced filtering options.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
async def get_filtered_audit_logs(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    object_type: Optional[str] = Query(None, description="Filter by object type"),
    action: Optional[str] = Query(None, description="Filter by action"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session ID"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    start_date: Optional[str] = Query(None, description="Filter by start date (ISO format)"),
    end_date: Optional[str] = Query(None, description="Filter by end date (ISO format)"),
    current_user: ValidatedUser = None,
    audit_log_service: AuditLogServiceDep = None
) -> List[Dict[str, Any]]:
    try:
        from datetime import datetime
        
        # Build filters
        filters = AuditLogFilter(
            object_type=object_type,
            action=action,
            user_id=user_id,
            audit_session_id=audit_session_id,
            compliance_domain=compliance_domain,
            risk_level=risk_level,
            performed_after=datetime.fromisoformat(start_date) if start_date else None,
            performed_before=datetime.fromisoformat(end_date) if end_date else None
        )
        
        logs = await audit_log_service.list_audit_logs(
            user_id=current_user.id,
            skip=skip,
            limit=limit,
            filters=filters
        )
        return [log.to_dict() for log in logs]
    except ValueError as e:
        logger.error(f"Invalid date format in filtered audit logs: {e}")
        raise HTTPException(status_code=400, detail="Invalid date format. Use ISO format (YYYY-MM-DDTHH:MM:SS)")
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to get filtered audit logs: {e}")
        raise HTTPException(status_code=400 if isinstance(e, ValidationException) else 403, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error getting filtered audit logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error getting filtered audit logs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")