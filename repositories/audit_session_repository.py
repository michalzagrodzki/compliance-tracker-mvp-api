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
            session_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            
            session_data = session_create.model_dump()
            session_data.update({
                "id": session_id,
                "is_active": True,
                "total_queries": 0,
                "started_at": now.isoformat()
            })
            
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
                    field="session_id",
                    value=session_id
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
                    field="session_id",
                    value=session_id
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
            
            query = self._apply_ordering(query, order_by or "-started_at")
            
            query = query.range(skip, skip + limit - 1)
            
            result = query.execute()
            
            sessions = [AuditSession.from_dict(session_data) for session_data in result.data]
            
            logger.debug(f"Listed {len(sessions)} audit sessions with filters: {filters}")
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to list audit sessions: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit sessions",
                error_code="AUDIT_SESSION_LIST_FAILED"
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
                    "total_queries": new_count
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
