"""
Audit Session repository implementation using Supabase.
"""

from typing import Optional, List, Any
from datetime import datetime, timezone
import uuid

from repositories.base import SupabaseRepository
from entities.audit_session import (
    AuditSession,
    AuditSessionCreate,
    AuditSessionUpdate,
    AuditSessionFilter,
    AuditSessionStatistics
)
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException
)
from common.logging import get_logger

logger = get_logger("audit_session_repository")


class AuditSessionRepository(SupabaseRepository[AuditSession]):
    """
    Repository for AuditSession entity operations with Supabase.
    """

    def __init__(self, supabase_client, table_name: str = "audit_sessions"):
        super().__init__(supabase_client, table_name)

    def _ensure_string(self, value: Any) -> str:
        """Ensure value is a string for UUID operations."""
        if isinstance(value, uuid.UUID):
            return str(value)
        return str(value) if value is not None else ""

    async def create(self, session_create: AuditSessionCreate) -> AuditSession:
        """Create a new audit session."""
        try:
            # Generate ID and timestamps
            session_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            
            # Convert to dict and add required fields
            session_data = session_create.model_dump()
            session_data.update({
                "id": session_id,
                "is_active": True,
                "total_queries": 0,
                "started_at": now.isoformat(),
                "created_at": now.isoformat(),
                "updated_at": now.isoformat()
            })
            
            # Insert into database
            result = self.supabase.table(self.table_name).insert(session_data).execute()
            
            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to create audit session",
                    error_code="AUDIT_SESSION_CREATION_FAILED"
                )
            
            # Convert back to AuditSession entity
            created_session = AuditSession.from_dict(result.data[0])
            
            logger.info(f"Created audit session: {created_session.session_name} (ID: {created_session.id})")
            return created_session
            
        except Exception as e:
            logger.error(f"Failed to create audit session: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create audit session",
                error_code="AUDIT_SESSION_CREATION_FAILED",
                context={"session_name": session_create.session_name}
            )

    async def get_by_id(self, session_id: str) -> Optional[AuditSession]:
        """Retrieve an audit session by ID."""
        try:
            # Validate UUID format
            session_id = self._ensure_string(session_id)
            try:
                uuid.UUID(session_id)
            except ValueError:
                raise ValidationException(
                    detail="Invalid session_id format (must be UUID)",
                    error_code="INVALID_UUID_FORMAT"
                )
            
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("id", session_id)\
                .execute()
            
            if not result.data:
                return None
            
            return AuditSession.from_dict(result.data[0])
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to get audit session by ID {session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit session",
                error_code="AUDIT_SESSION_RETRIEVAL_FAILED",
                context={"session_id": session_id}
            )

    async def get_by_user(
        self, 
        user_id: str, 
        skip: int = 0, 
        limit: int = 100,
        active_only: bool = False
    ) -> List[AuditSession]:
        """Retrieve audit sessions by user ID."""
        try:
            user_id = self._ensure_string(user_id)
            
            query = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("user_id", user_id)
            
            if active_only:
                query = query.eq("is_active", True)
            
            result = query\
                .order("started_at", desc=True)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            sessions = [AuditSession.from_dict(session_data) for session_data in result.data]
            
            logger.debug(f"Retrieved {len(sessions)} audit sessions for user {user_id}")
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to get audit sessions for user {user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit sessions",
                error_code="AUDIT_SESSION_USER_RETRIEVAL_FAILED",
                context={"user_id": user_id}
            )

    async def get_by_domain(
        self, 
        compliance_domain: str, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[AuditSession]:
        """Retrieve audit sessions by compliance domain."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("compliance_domain", compliance_domain)\
                .order("started_at", desc=True)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            sessions = [AuditSession.from_dict(session_data) for session_data in result.data]
            
            logger.debug(f"Retrieved {len(sessions)} audit sessions for domain {compliance_domain}")
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to get audit sessions for domain {compliance_domain}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit sessions",
                error_code="AUDIT_SESSION_DOMAIN_RETRIEVAL_FAILED",
                context={"compliance_domain": compliance_domain}
            )

    async def update(self, session_id: str, update_data: AuditSessionUpdate) -> Optional[AuditSession]:
        """Update an audit session by ID."""
        try:
            # Validate UUID format
            session_id = self._ensure_string(session_id)
            try:
                uuid.UUID(session_id)
            except ValueError:
                raise ValidationException(
                    detail="Invalid session_id format (must be UUID)",
                    error_code="INVALID_UUID_FORMAT"
                )
            
            # Check if session exists
            if not await self.exists(session_id):
                raise ResourceNotFoundException(
                    resource_type="AuditSession",
                    resource_id=session_id
                )
            
            # Convert update data to dict, excluding None values
            update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
            
            if not update_dict:
                # No changes to apply
                return await self.get_by_id(session_id)
            
            # Add updated timestamp
            update_dict["updated_at"] = datetime.now(timezone.utc).isoformat()
            
            # Handle datetime fields
            if "ended_at" in update_dict and update_dict["ended_at"] is not None:
                if isinstance(update_dict["ended_at"], datetime):
                    update_dict["ended_at"] = update_dict["ended_at"].isoformat()
            
            # Update in database
            result = self.supabase.table(self.table_name)\
                .update(update_dict)\
                .eq("id", session_id)\
                .execute()
            
            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to update audit session",
                    error_code="AUDIT_SESSION_UPDATE_FAILED"
                )
            
            updated_session = AuditSession.from_dict(result.data[0])
            logger.info(f"Updated audit session: {updated_session.session_name} (ID: {session_id})")
            return updated_session
            
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception as e:
            logger.error(f"Failed to update audit session {session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update audit session",
                error_code="AUDIT_SESSION_UPDATE_FAILED",
                context={"session_id": session_id}
            )

    async def delete(self, session_id: str, soft_delete: bool = True) -> bool:
        """Delete an audit session by ID."""
        try:
            # Validate UUID format
            session_id = self._ensure_string(session_id)
            try:
                uuid.UUID(session_id)
            except ValueError:
                raise ValidationException(
                    detail="Invalid session_id format (must be UUID)",
                    error_code="INVALID_UUID_FORMAT"
                )
            
            # Check if session exists first to get details for logging
            existing_session = await self.get_by_id(session_id)
            if not existing_session:
                raise ResourceNotFoundException(
                    resource_type="AuditSession",
                    resource_id=session_id
                )
            
            if soft_delete:
                # Soft delete: deactivate and set end time
                update_data = {
                    "is_active": False,
                    "ended_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat()
                }
                
                result = self.supabase.table(self.table_name)\
                    .update(update_data)\
                    .eq("id", session_id)\
                    .execute()
                
                if result.data:
                    logger.info(f"Soft deleted audit session: {existing_session.session_name} (ID: {session_id})")
                    return True
            else:
                # Hard delete: actually remove the record
                result = self.supabase.table(self.table_name)\
                    .delete()\
                    .eq("id", session_id)\
                    .execute()
                
                if result.data:
                    logger.info(f"Hard deleted audit session: {existing_session.session_name} (ID: {session_id})")
                    return True
            
            return False
            
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception as e:
            logger.error(f"Failed to delete audit session {session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to delete audit session",
                error_code="AUDIT_SESSION_DELETION_FAILED",
                context={"session_id": session_id}
            )

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[AuditSessionFilter] = None,
        order_by: Optional[str] = None
    ) -> List[AuditSession]:
        """List audit sessions with optional filtering and pagination."""
        try:
            query = self.supabase.table(self.table_name).select("*")
            
            # Apply filters
            if filters:
                filter_dict = {}
                for field, value in filters.model_dump().items():
                    if value is not None:
                        if field == "session_name_contains":
                            # Use ilike for partial name matching
                            query = query.ilike("session_name", f"%{value}%")
                        elif field in ["started_after", "ended_after"]:
                            date_field = field.replace("_after", "_at")
                            query = query.gte(date_field, value.isoformat())
                        elif field in ["started_before", "ended_before"]:
                            date_field = field.replace("_before", "_at")
                            query = query.lte(date_field, value.isoformat())
                        else:
                            filter_dict[field] = value
                
                query = self._build_filters(query, filter_dict)
            
            # Apply ordering (default to started_at desc)
            query = self._apply_ordering(query, order_by or "-started_at")
            
            # Apply pagination
            query = query.range(skip, skip + limit - 1)
            
            result = query.execute()
            
            # Convert to AuditSession entities
            sessions = [AuditSession.from_dict(session_data) for session_data in result.data]
            
            logger.debug(f"Listed {len(sessions)} audit sessions with filters: {filters}")
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to list audit sessions: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit sessions",
                error_code="AUDIT_SESSION_LIST_FAILED"
            )

    async def search(
        self,
        compliance_domain: Optional[str] = None,
        user_id: Optional[str] = None,
        is_active: Optional[bool] = None,
        started_after: Optional[datetime] = None,
        started_before: Optional[datetime] = None,
        session_name_query: Optional[str] = None,
        skip: int = 0,
        limit: int = 100
    ) -> List[AuditSession]:
        """Search audit sessions with multiple criteria."""
        try:
            query = self.supabase.table(self.table_name).select("*")
            
            # Build filters
            if compliance_domain:
                query = query.eq("compliance_domain", compliance_domain)
            
            if user_id:
                user_id = self._ensure_string(user_id)
                query = query.eq("user_id", user_id)
            
            if is_active is not None:
                query = query.eq("is_active", is_active)
            
            if started_after:
                query = query.gte("started_at", started_after.isoformat())
            
            if started_before:
                query = query.lte("started_at", started_before.isoformat())
            
            if session_name_query:
                query = query.ilike("session_name", f"%{session_name_query}%")
            
            result = query\
                .order("started_at", desc=True)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            sessions = [AuditSession.from_dict(session_data) for session_data in result.data]
            
            logger.debug(f"Search returned {len(sessions)} audit sessions")
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to search audit sessions: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to search audit sessions",
                error_code="AUDIT_SESSION_SEARCH_FAILED"
            )

    async def increment_queries(self, session_id: str) -> Optional[AuditSession]:
        """Increment the query count for an audit session."""
        try:
            session_id = self._ensure_string(session_id)
            
            # Get current session to increment query count
            current_session = await self.get_by_id(session_id)
            if not current_session:
                raise ResourceNotFoundException(
                    resource_type="AuditSession",
                    resource_id=session_id
                )
            
            new_count = current_session.total_queries + 1
            
            # Update query count
            result = self.supabase.table(self.table_name)\
                .update({
                    "total_queries": new_count,
                    "updated_at": datetime.now(timezone.utc).isoformat()
                })\
                .eq("id", session_id)\
                .execute()
            
            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to increment query count",
                    error_code="AUDIT_SESSION_QUERY_INCREMENT_FAILED"
                )
            
            updated_session = AuditSession.from_dict(result.data[0])
            logger.debug(f"Incremented queries for session {session_id} to {new_count}")
            return updated_session
            
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Failed to increment queries for session {session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to increment query count",
                error_code="AUDIT_SESSION_QUERY_INCREMENT_FAILED",
                context={"session_id": session_id}
            )

    async def get_statistics(
        self,
        compliance_domain: Optional[str] = None,
        user_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> AuditSessionStatistics:
        """Get statistics about audit sessions."""
        try:
            # Build base query
            query = self.supabase.table(self.table_name).select("*")
            
            if compliance_domain:
                query = query.eq("compliance_domain", compliance_domain)
            
            if user_id:
                user_id = self._ensure_string(user_id)
                query = query.eq("user_id", user_id)
            
            if start_date:
                query = query.gte("started_at", start_date.isoformat())
            
            if end_date:
                query = query.lte("started_at", end_date.isoformat())
            
            result = query.execute()
            sessions_data = result.data
            
            # Convert to entities for easier processing
            sessions = [AuditSession.from_dict(session_data) for session_data in sessions_data]
            
            # Calculate statistics
            total_sessions = len(sessions)
            active_sessions = len([s for s in sessions if s.is_active])
            completed_sessions = total_sessions - active_sessions
            
            total_queries = sum(s.total_queries for s in sessions)
            avg_queries_per_session = total_queries / total_sessions if total_sessions > 0 else 0
            
            # Calculate average session duration for completed sessions
            completed_sessions_with_duration = [
                s for s in sessions 
                if s.ended_at is not None and not s.is_active
            ]
            
            avg_duration_minutes = None
            if completed_sessions_with_duration:
                durations = [s.get_duration_minutes() for s in completed_sessions_with_duration]
                valid_durations = [d for d in durations if d is not None]
                if valid_durations:
                    avg_duration_minutes = sum(valid_durations) / len(valid_durations)
            
            # Domain breakdown
            domain_counts = {}
            for session in sessions:
                domain = session.compliance_domain
                domain_counts[domain] = domain_counts.get(domain, 0) + 1
            
            # User breakdown
            user_counts = {}
            for session in sessions:
                user = session.user_id
                user_counts[user] = user_counts.get(user, 0) + 1
            
            statistics = AuditSessionStatistics(
                total_sessions=total_sessions,
                active_sessions=active_sessions,
                completed_sessions=completed_sessions,
                total_queries=total_queries,
                avg_queries_per_session=round(avg_queries_per_session, 2),
                sessions_by_domain=domain_counts,
                sessions_by_user=user_counts,
                avg_session_duration_minutes=round(avg_duration_minutes, 2) if avg_duration_minutes else None,
                filters_applied={
                    "compliance_domain": compliance_domain,
                    "user_id": user_id,
                    "start_date": start_date.isoformat() if start_date else None,
                    "end_date": end_date.isoformat() if end_date else None
                }
            )
            
            logger.debug(f"Generated statistics for {total_sessions} audit sessions")
            return statistics
            
        except Exception as e:
            logger.error(f"Failed to get audit session statistics: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit session statistics",
                error_code="AUDIT_SESSION_STATISTICS_FAILED"
            )