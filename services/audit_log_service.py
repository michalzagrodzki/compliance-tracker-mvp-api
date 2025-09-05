"""
Audit Log service using Repository pattern.
"""

from typing import Optional, List
from datetime import datetime

from entities.audit_log import (
    AuditLog, 
    AuditLogCreate, 
    AuditLogFilter,
    AuditLogStatistics
)
from repositories.audit_log_repository import AuditLogRepository
from repositories.user_repository import UserRepository
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException,
    AuthorizationException
)
from common.logging import get_logger, log_business_event, log_performance

logger = get_logger("audit_log_service")


class AuditLogService:
    """
    Audit Log service using Repository pattern.
    Handles business logic for audit log management.
    """

    def __init__(self, audit_log_repository: AuditLogRepository, user_repository: UserRepository):
        self.audit_log_repository = audit_log_repository
        self.user_repository = user_repository

    async def create_audit_log(
        self, 
        audit_log_create: AuditLogCreate, 
        requesting_user_id: str
    ) -> AuditLog:
        """Create a new audit log entry."""
        try:
            import time
            start_time = time.time()
            
            # Validate requesting user exists and is active
            requesting_user = await self.user_repository.get_by_id(requesting_user_id)
            if not requesting_user or not requesting_user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive requesting user",
                    field="requesting_user_id",
                    value=requesting_user_id
                )
            
            # Only allow admins to create audit logs directly through API
            # (Most audit logs are created automatically by the system)
            if not requesting_user.is_admin():
                raise AuthorizationException(
                    detail="Only administrators can create audit log entries directly",
                    error_code="ADMIN_ACCESS_REQUIRED"
                )
            
            # Create the audit log entry
            created_log = await self.audit_log_repository.create(audit_log_create)
            
            # Log the creation (meta-audit log)
            log_business_event(
                event_type="AUDIT_LOG_CREATED",
                entity_type="audit_log",
                entity_id=created_log.id,
                action="create",
                user_id=requesting_user_id,
                details={
                    "target_object_type": created_log.object_type,
                    "target_object_id": created_log.object_id,
                    "target_action": created_log.action,
                    "target_user_id": created_log.user_id
                }
            )
            
            # Log performance
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="create_audit_log",
                duration_ms=duration_ms,
                success=True,
                item_count=1
            )
            
            return created_log
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create audit log entry",
                error_code="AUDIT_LOG_CREATION_FAILED",
                context={"object_type": audit_log_create.object_type, "action": audit_log_create.action}
            )

    async def get_audit_log_by_id(self, log_id: str, user_id: str) -> AuditLog:
        """Get an audit log entry by ID with access control."""
        try:
            # Get the audit log entry
            audit_log = await self.audit_log_repository.get_by_id(log_id)
            if not audit_log:
                raise ResourceNotFoundException(
                    resource_type="AuditLog",
                    resource_id=log_id
                )
            
            # Check user access
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            # Allow access if user is admin or if the audit log concerns their domain
            if not user.is_admin():
                if audit_log.compliance_domain and not user.can_access_domain(audit_log.compliance_domain):
                    raise AuthorizationException(
                        detail=f"Access denied to audit logs for compliance domain: {audit_log.compliance_domain}",
                        error_code="DOMAIN_ACCESS_DENIED"
                    )
            
            return audit_log
            
        except (ResourceNotFoundException, ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to get audit log {log_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit log entry",
                error_code="AUDIT_LOG_RETRIEVAL_FAILED",
                context={"log_id": log_id}
            )

    async def list_audit_logs(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[AuditLogFilter] = None
    ) -> List[AuditLog]:
        """List audit log entries with access control."""
        try:
            import time
            start_time = time.time()
            
            # Get user and their accessible domains
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            # If user is not admin, filter by their accessible domains
            if not user.is_admin():
                # If a specific domain is requested, check access
                if filters and filters.compliance_domain:
                    if not user.can_access_domain(filters.compliance_domain):
                        raise AuthorizationException(
                            detail=f"Access denied to audit logs for compliance domain: {filters.compliance_domain}",
                            error_code="DOMAIN_ACCESS_DENIED"
                        )
                
                # Get audit logs and filter by accessible domains
                logs = await self.audit_log_repository.list(skip, limit, filters)
                
                # Filter out logs from domains the user can't access
                filtered_logs = []
                for log in logs:
                    if not log.compliance_domain or user.can_access_domain(log.compliance_domain):
                        filtered_logs.append(log)
                
                logs = filtered_logs
            else:
                # Admin can see all audit logs
                logs = await self.audit_log_repository.list(skip, limit, filters)
            
            # Log performance
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="list_audit_logs",
                duration_ms=duration_ms,
                success=True,
                item_count=len(logs)
            )
            
            return logs
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to list audit logs: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit log entries",
                error_code="AUDIT_LOG_LIST_FAILED"
            )

    async def get_audit_logs_by_user(self, target_user_id: str, requesting_user_id: str, skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get audit log entries for a specific user with access control."""
        try:
            # Validate requesting user
            requesting_user = await self.user_repository.get_by_id(requesting_user_id)
            if not requesting_user:
                raise ValidationException(
                    detail="Invalid requesting user",
                    field="requesting_user_id",
                    value=requesting_user_id
                )
            
            # Non-admin users can only see their own audit logs
            if not requesting_user.is_admin() and target_user_id != requesting_user_id:
                raise AuthorizationException(
                    detail="Access denied to other user's audit logs",
                    error_code="USER_ACCESS_DENIED"
                )
            
            logs = await self.audit_log_repository.get_by_user(target_user_id, skip, limit)
            
            # Filter by accessible domains if not admin
            if not requesting_user.is_admin():
                logs = [log for log in logs if not log.compliance_domain or requesting_user.can_access_domain(log.compliance_domain)]
            
            return logs
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to get audit logs by user {target_user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit logs by user",
                error_code="AUDIT_LOG_USER_RETRIEVAL_FAILED",
                context={"target_user_id": target_user_id}
            )

    async def get_audit_logs_by_object(self, object_type: str, object_id: str, user_id: str, skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get audit log entries for a specific object with access control."""
        try:
            # Validate user access
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            logs = await self.audit_log_repository.get_by_object(object_type, object_id, skip, limit)
            
            # Filter by accessible domains if not admin
            if not user.is_admin():
                logs = [log for log in logs if not log.compliance_domain or user.can_access_domain(log.compliance_domain)]
            
            return logs
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to get audit logs by object {object_type}/{object_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit logs by object",
                error_code="AUDIT_LOG_OBJECT_RETRIEVAL_FAILED",
                context={"object_type": object_type, "object_id": object_id}
            )

    async def get_audit_logs_by_audit_session(self, audit_session_id: str, user_id: str, skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get audit log entries for a specific audit session with access control."""
        try:
            # Validate user access
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            logs = await self.audit_log_repository.get_by_audit_session(audit_session_id, skip, limit)
            
            # Filter by accessible domains if not admin
            if not user.is_admin():
                logs = [log for log in logs if not log.compliance_domain or user.can_access_domain(log.compliance_domain)]
            
            return logs
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to get audit logs by audit session {audit_session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit logs by audit session",
                error_code="AUDIT_LOG_AUDIT_SESSION_RETRIEVAL_FAILED",
                context={"audit_session_id": audit_session_id}
            )

    async def get_audit_logs_by_compliance_domain(self, domain: str, user_id: str, skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get audit log entries for a specific compliance domain with access control."""
        try:
            # Validate user access to domain
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            if not (user.is_admin() or user.can_access_domain(domain)):
                raise AuthorizationException(
                    detail=f"Access denied to audit logs for compliance domain: {domain}",
                    error_code="DOMAIN_ACCESS_DENIED"
                )
            
            return await self.audit_log_repository.get_by_compliance_domain(domain, skip, limit)
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to get audit logs by domain {domain}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit logs by domain",
                error_code="AUDIT_LOG_DOMAIN_RETRIEVAL_FAILED",
                context={"domain": domain}
            )

    async def get_recent_activity(self, user_id: str, hours: int = 24, skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get recent audit log entries with access control."""
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            logs = await self.audit_log_repository.get_recent_activity(hours, skip, limit)
            
            # Filter by accessible domains if not admin
            if not user.is_admin():
                logs = [log for log in logs if not log.compliance_domain or user.can_access_domain(log.compliance_domain)]
            
            return logs
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to get recent audit activity: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve recent audit activity",
                error_code="AUDIT_LOG_RECENT_RETRIEVAL_FAILED"
            )

# Factory function
def create_audit_log_service(
    audit_log_repository: AuditLogRepository,
    user_repository: UserRepository
) -> AuditLogService:
    """Factory function to create AuditLogService instance."""
    return AuditLogService(audit_log_repository, user_repository)