"""
Audit Log repository implementation using Supabase.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import uuid

from repositories.base import SupabaseRepository
from entities.audit_log import (
    AuditLog, 
    AuditLogCreate, 
    AuditLogFilter,
    AuditLogStatistics
)
from common.exceptions import (
    ValidationException,
    BusinessLogicException
)
from common.logging import get_logger

logger = get_logger("audit_log_repository")


class AuditLogRepository(SupabaseRepository[AuditLog]):
    """
    Repository for AuditLog entity operations with Supabase.
    """

    def __init__(self, supabase_client, table_name: str = "audit_log"):
        super().__init__(supabase_client, table_name)

    def _ensure_string(self, value: Any) -> Optional[str]:
        """Convert UUID objects to strings, pass through None and strings as-is"""
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return str(value)
        return str(value)

    async def create(self, audit_log_create: AuditLogCreate) -> AuditLog:
        """Create a new audit log entry."""
        try:
            # Generate ID and timestamp
            log_id = str(uuid.uuid4())
            now = datetime.utcnow()
            
            # Convert to dict and add required fields
            log_data = audit_log_create.model_dump()
            
            # Ensure UUID fields are converted to strings
            log_data.update({
                "id": log_id,
                "object_id": self._ensure_string(log_data["object_id"]),
                "user_id": self._ensure_string(log_data["user_id"]),
                "performed_at": now.isoformat()
            })
            
            # Handle optional UUID fields
            if log_data.get("audit_session_id"):
                log_data["audit_session_id"] = self._ensure_string(log_data["audit_session_id"])
            
            # Insert into database
            result = self.supabase.table(self.table_name).insert(log_data).execute()
            
            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to create audit log entry",
                    error_code="AUDIT_LOG_CREATION_FAILED"
                )
            
            # Convert back to AuditLog entity
            created_log = AuditLog.from_dict(result.data[0])
            
            logger.debug(f"Created audit log: {created_log.object_type}/{created_log.object_id} - {created_log.action} (ID: {created_log.id})")
            return created_log
            
        except Exception as e:
            logger.error(f"Failed to create audit log entry: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create audit log entry",
                error_code="AUDIT_LOG_CREATION_FAILED",
                context={"object_type": audit_log_create.object_type, "action": audit_log_create.action}
            )

    async def get_by_id(self, log_id: str) -> Optional[AuditLog]:
        """Retrieve an audit log entry by ID."""
        try:
            # Validate UUID format
            try:
                uuid.UUID(log_id)
            except ValueError:
                raise ValidationException(
                    detail="Invalid log_id format (must be UUID)",
                    error_code="INVALID_UUID_FORMAT"
                )
            
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("id", self._ensure_string(log_id))\
                .execute()
            
            if not result.data:
                return None
            
            return AuditLog.from_dict(result.data[0])
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to get audit log by ID {log_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit log entry",
                error_code="AUDIT_LOG_RETRIEVAL_FAILED",
                context={"log_id": log_id}
            )

    async def update(self, log_id: str, update_data: Dict[str, Any]) -> Optional[AuditLog]:
        """Update an audit log entry by ID. Note: Audit logs are typically immutable."""
        raise BusinessLogicException(
            detail="Audit log entries are immutable and cannot be updated",
            error_code="AUDIT_LOG_IMMUTABLE"
        )

    async def delete(self, log_id: str) -> bool:
        """Delete an audit log entry by ID. Note: Audit logs should typically not be deleted."""
        try:
            # Validate UUID format
            try:
                uuid.UUID(log_id)
            except ValueError:
                raise ValidationException(
                    detail="Invalid log_id format (must be UUID)",
                    error_code="INVALID_UUID_FORMAT"
                )
            
            result = self.supabase.table(self.table_name)\
                .delete()\
                .eq("id", self._ensure_string(log_id))\
                .execute()
            
            if result.data:
                logger.warning(f"Deleted audit log entry: {log_id}")
                return True
            
            return False
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to delete audit log {log_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to delete audit log entry",
                error_code="AUDIT_LOG_DELETION_FAILED",
                context={"log_id": log_id}
            )

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[AuditLogFilter] = None,
        order_by: Optional[str] = None
    ) -> List[AuditLog]:
        """List audit log entries with optional filtering and pagination."""
        try:
            query = self.supabase.table(self.table_name).select("*")
            
            # Apply filters
            if filters:
                filter_dict = {}
                for field, value in filters.model_dump().items():
                    if value is not None:
                        if field in ["performed_after", "performed_before"]:
                            date_field = "performed_at"
                            if field == "performed_after":
                                query = query.gte(date_field, value.isoformat())
                            else:
                                query = query.lte(date_field, value.isoformat())
                        elif field == "tags" and value:
                            # Handle tag filtering
                            mode = filters.tags_match_mode or "any"
                            if mode.lower() == "all":
                                query = query.contains("tags", value)
                            elif mode.lower() == "exact":
                                query = query.eq("tags", value)
                            else:  # any
                                query = query.overlaps("tags", value)
                        elif field not in ["tags_match_mode"]:
                            # Handle string fields that need UUID conversion
                            if field in ["object_id", "user_id", "audit_session_id"]:
                                filter_dict[field] = self._ensure_string(value)
                            else:
                                filter_dict[field] = value
                
                query = self._build_filters(query, filter_dict)
            
            # Apply ordering (default to performed_at desc)
            query = self._apply_ordering(query, order_by or "-performed_at")
            
            # Apply pagination
            query = query.range(skip, skip + limit - 1)
            
            result = query.execute()
            
            # Convert to AuditLog entities
            logs = [AuditLog.from_dict(log_data) for log_data in result.data]
            
            logger.debug(f"Listed {len(logs)} audit log entries with filters: {filters}")
            return logs
            
        except Exception as e:
            logger.error(f"Failed to list audit log entries: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit log entries",
                error_code="AUDIT_LOG_LIST_FAILED"
            )

    async def get_by_user(self, user_id: str, skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get all audit log entries for a specific user."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("user_id", self._ensure_string(user_id))\
                .order("performed_at", desc=True)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            logs = [AuditLog.from_dict(log_data) for log_data in result.data]
            
            logger.debug(f"Found {len(logs)} audit log entries for user: {user_id}")
            return logs
            
        except Exception as e:
            logger.error(f"Failed to get audit logs by user {user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit logs by user",
                error_code="AUDIT_LOG_USER_RETRIEVAL_FAILED",
                context={"user_id": user_id}
            )

    async def get_by_object(self, object_type: str, object_id: str, skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get all audit log entries for a specific object."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("object_type", object_type)\
                .eq("object_id", self._ensure_string(object_id))\
                .order("performed_at", desc=True)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            logs = [AuditLog.from_dict(log_data) for log_data in result.data]
            
            logger.debug(f"Found {len(logs)} audit log entries for {object_type}/{object_id}")
            return logs
            
        except Exception as e:
            logger.error(f"Failed to get audit logs by object {object_type}/{object_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit logs by object",
                error_code="AUDIT_LOG_OBJECT_RETRIEVAL_FAILED",
                context={"object_type": object_type, "object_id": object_id}
            )

    async def get_by_audit_session(self, audit_session_id: str, skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get all audit log entries for a specific audit session."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("audit_session_id", self._ensure_string(audit_session_id))\
                .order("performed_at", desc=True)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            logs = [AuditLog.from_dict(log_data) for log_data in result.data]
            
            logger.debug(f"Found {len(logs)} audit log entries for audit session: {audit_session_id}")
            return logs
            
        except Exception as e:
            logger.error(f"Failed to get audit logs by audit session {audit_session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit logs by audit session",
                error_code="AUDIT_LOG_AUDIT_SESSION_RETRIEVAL_FAILED",
                context={"audit_session_id": audit_session_id}
            )

    async def get_by_compliance_domain(self, domain: str, skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get all audit log entries for a specific compliance domain."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("compliance_domain", domain)\
                .order("performed_at", desc=True)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            logs = [AuditLog.from_dict(log_data) for log_data in result.data]
            
            logger.debug(f"Found {len(logs)} audit log entries for domain: {domain}")
            return logs
            
        except Exception as e:
            logger.error(f"Failed to get audit logs by domain {domain}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit logs by domain",
                error_code="AUDIT_LOG_DOMAIN_RETRIEVAL_FAILED",
                context={"domain": domain}
            )

    async def get_recent_activity(self, hours: int = 24, skip: int = 0, limit: int = 100) -> List[AuditLog]:
        """Get recent audit log entries within the specified hours."""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .gte("performed_at", cutoff_time.isoformat())\
                .order("performed_at", desc=True)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            logs = [AuditLog.from_dict(log_data) for log_data in result.data]
            
            logger.debug(f"Found {len(logs)} recent audit log entries (last {hours} hours)")
            return logs
            
        except Exception as e:
            logger.error(f"Failed to get recent audit logs: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve recent audit logs",
                error_code="AUDIT_LOG_RECENT_RETRIEVAL_FAILED",
                context={"hours": hours}
            )

    async def get_statistics(self, compliance_domain: Optional[str] = None) -> AuditLogStatistics:
        """Get statistics about audit log entries."""
        try:
            base_query = self.supabase.table(self.table_name)
            
            if compliance_domain:
                base_query = base_query.eq("compliance_domain", compliance_domain)
            
            # Get all logs for statistics
            result = base_query.select("*").execute()
            logs_data = result.data
            
            if not logs_data:
                return AuditLogStatistics()
            
            logs = [AuditLog.from_dict(log_data) for log_data in logs_data]
            
            # Calculate statistics
            total_entries = len(logs)
            unique_users = len(set(log.user_id for log in logs))
            unique_objects = len(set(f"{log.object_type}:{log.object_id}" for log in logs))
            
            # Action breakdown
            actions_breakdown = {}
            for log in logs:
                actions_breakdown[log.action] = actions_breakdown.get(log.action, 0) + 1
            
            # Object types breakdown
            object_types_breakdown = {}
            for log in logs:
                object_types_breakdown[log.object_type] = object_types_breakdown.get(log.object_type, 0) + 1
            
            # Risk levels breakdown
            risk_levels_breakdown = {}
            for log in logs:
                if log.risk_level:
                    risk_levels_breakdown[log.risk_level] = risk_levels_breakdown.get(log.risk_level, 0) + 1
            
            # Compliance domains breakdown
            compliance_domains_breakdown = {}
            for log in logs:
                if log.compliance_domain:
                    compliance_domains_breakdown[log.compliance_domain] = compliance_domains_breakdown.get(log.compliance_domain, 0) + 1
            
            # Recent activity (last 24 hours)
            cutoff_time = datetime.utcnow() - timedelta(hours=24)
            recent_activity_count = sum(1 for log in logs if log.performed_at and log.performed_at >= cutoff_time)
            
            statistics = AuditLogStatistics(
                total_entries=total_entries,
                unique_users=unique_users,
                unique_objects=unique_objects,
                actions_breakdown=actions_breakdown,
                object_types_breakdown=object_types_breakdown,
                risk_levels_breakdown=risk_levels_breakdown,
                compliance_domains_breakdown=compliance_domains_breakdown,
                recent_activity_count=recent_activity_count
            )
            
            logger.debug(f"Generated audit log statistics: {statistics.dict()}")
            return statistics
            
        except Exception as e:
            logger.error(f"Failed to get audit log statistics: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit log statistics",
                error_code="AUDIT_LOG_STATISTICS_FAILED",
                context={"compliance_domain": compliance_domain}
            )