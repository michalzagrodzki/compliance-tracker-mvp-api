"""
Audit Session service using Repository pattern.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from entities.audit_session import (
    AuditSession,
    AuditSessionCreate,
    AuditSessionUpdate,
    AuditSessionFilter,
    AuditSessionStatistics
)
from repositories.audit_session_repository import AuditSessionRepository
from repositories.user_repository import UserRepository
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException,
    AuthorizationException
)
from common.logging import get_logger, log_business_event, log_performance
from config.config import settings
from db.supabase_client import create_supabase_client

logger = get_logger("audit_session_service")


class AuditSessionService:
    """
    Audit Session service using Repository pattern.
    Handles business logic for audit session management.
    """

    def __init__(self, audit_session_repository: AuditSessionRepository, user_repository: UserRepository):
        self.session_repository = audit_session_repository
        self.user_repository = user_repository

    async def create_session(
        self,
        session_create: AuditSessionCreate,
        user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditSession:
        """Create a new audit session."""
        try:
            import time
            start_time = time.time()
            
            # Validate user exists and is active
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive user",
                    field="user_id",
                    value=user_id
                )
            
            # Check if user has appropriate access (admin or compliance_officer can create sessions)
            if not (user.is_admin() or user.is_compliance_officer()):
                raise AuthorizationException(
                    detail="Only administrators and compliance officers can create audit sessions",
                    error_code="INSUFFICIENT_PERMISSIONS"
                )
            
            # Verify the user_id in the request matches the authenticated user
            if session_create.user_id != user_id:
                raise ValidationException(
                    detail="Cannot create audit session for another user",
                    field="user_id",
                    value=session_create.user_id
                )
            
            # Check domain access if the user is not an admin
            if not user.is_admin() and not user.can_access_domain(session_create.compliance_domain):
                raise AuthorizationException(
                    detail=f"Access denied to compliance domain: {session_create.compliance_domain}",
                    error_code="DOMAIN_ACCESS_DENIED"
                )
            
            # Create the session
            created_session = await self.session_repository.create(session_create)
            
            # Log business event
            log_business_event(
                event_type="AUDIT_SESSION_CREATED",
                entity_type="audit_session",
                entity_id=created_session.id,
                action="create",
                user_id=user_id,
                details={
                    "session_name": created_session.session_name,
                    "compliance_domain": created_session.compliance_domain,
                    "ip_address": ip_address,
                    "user_agent": user_agent
                }
            )
            
            # Log performance
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="create_audit_session",
                duration_ms=duration_ms,
                success=True,
                item_count=1
            )
            
            return created_session
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to create audit session: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create audit session",
                error_code="AUDIT_SESSION_CREATION_FAILED",
                context={"session_name": session_create.session_name}
            )

    async def get_session_by_id(self, session_id: str, user_id: str) -> AuditSession:
        """Get an audit session by ID with access control."""
        try:
            # Get the session
            session = await self.session_repository.get_by_id(session_id)
            if not session:
                raise ResourceNotFoundException(
                    resource_type="AuditSession",
                    resource_id=session_id
                )
            
            # Validate user exists
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive user",
                    field="user_id",
                    value=user_id
                )
            
            # Check access rights - users can access their own sessions, admins can access all
            if not user.is_admin() and session.user_id != user_id:
                raise AuthorizationException(
                    detail="Access denied to audit session",
                    error_code="SESSION_ACCESS_DENIED"
                )
            
            # Check domain access if user is not admin
            if not user.is_admin() and not user.can_access_domain(session.compliance_domain):
                raise AuthorizationException(
                    detail=f"Access denied to compliance domain: {session.compliance_domain}",
                    error_code="DOMAIN_ACCESS_DENIED"
                )
            
            return session
            
        except (ResourceNotFoundException, ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to get audit session {session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit session",
                error_code="AUDIT_SESSION_RETRIEVAL_FAILED",
                context={"session_id": session_id}
            )

    async def update_session(
        self,
        session_id: str,
        update_data: AuditSessionUpdate,
        user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditSession:
        """Update an audit session with access control."""
        try:
            import time
            start_time = time.time()
            
            # Get existing session to check access
            existing_session = await self.get_session_by_id(session_id, user_id)
            
            # Validate user exists
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive user",
                    field="user_id",
                    value=user_id
                )
            
            # Check access rights - users can update their own sessions, admins can update all
            if not user.is_admin() and existing_session.user_id != user_id:
                raise AuthorizationException(
                    detail="Access denied to modify audit session",
                    error_code="SESSION_MODIFICATION_DENIED"
                )
            
            # Update the session
            updated_session = await self.session_repository.update(session_id, update_data)
            
            if updated_session:
                # Log business event
                log_business_event(
                    event_type="AUDIT_SESSION_UPDATED",
                    entity_type="audit_session",
                    entity_id=session_id,
                    action="update",
                    user_id=user_id,
                    details={
                        "session_name": updated_session.session_name,
                        "is_active": updated_session.is_active,
                        "has_summary": bool(updated_session.session_summary),
                        "ip_address": ip_address,
                        "user_agent": user_agent
                    }
                )
                
                # Log performance
                duration_ms = (time.time() - start_time) * 1000
                log_performance(
                    operation="update_audit_session",
                    duration_ms=duration_ms,
                    success=True,
                    item_count=1
                )
            
            return updated_session
            
        except (ResourceNotFoundException, ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to update audit session {session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update audit session",
                error_code="AUDIT_SESSION_UPDATE_FAILED",
                context={"session_id": session_id}
            )

    async def list_sessions(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[AuditSessionFilter] = None,
        order_by: Optional[str] = None
    ) -> List[AuditSession]:
        """List audit sessions with access control and filtering."""
        try:
            # Validate user exists
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive user",
                    field="user_id",
                    value=user_id
                )
            
            # Apply access control filters
            if filters is None:
                filters = AuditSessionFilter()
            
            # Non-admin users can only see their own sessions
            if not user.is_admin():
                filters.user_id = user_id
                
                # Filter by user's accessible domains
                if filters.compliance_domain and not user.can_access_domain(filters.compliance_domain):
                    # Return empty list if requesting inaccessible domain
                    return []
            
            # Get sessions from repository
            sessions = await self.session_repository.list(skip, limit, filters, order_by)
            
            # Additional domain filtering for non-admin users
            if not user.is_admin():
                sessions = [
                    session for session in sessions
                    if user.can_access_domain(session.compliance_domain)
                ]
            
            return sessions
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to list audit sessions for user {user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit sessions",
                error_code="AUDIT_SESSION_LIST_FAILED"
            )

    async def increment_session_queries(
        self,
        session_id: str,
        user_id: str
    ) -> AuditSession:
        """Increment query count for an audit session."""
        try:
            # Verify access to the session first
            await self.get_session_by_id(session_id, user_id)
            
            # Increment the query count
            updated_session = await self.session_repository.increment_queries(session_id)
            
            if updated_session:
                logger.debug(f"Incremented query count for session {session_id} to {updated_session.total_queries}")
            
            return updated_session
            
        except (ResourceNotFoundException, ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to increment queries for session {session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to increment session query count",
                error_code="AUDIT_SESSION_QUERY_INCREMENT_FAILED",
                context={"session_id": session_id}
            )

    async def close_session(
        self,
        session_id: str,
        user_id: str,
        session_summary: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditSession:
        """Close an active audit session."""
        try:
            # Create update data to close the session
            update_data = AuditSessionUpdate(
                is_active=False,
                ended_at=datetime.now(timezone.utc),
                session_summary=session_summary
            )
            
            # Update the session
            return await self.update_session(
                session_id=session_id,
                update_data=update_data,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
        except Exception as e:
            logger.error(f"Failed to close audit session {session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to close audit session",
                error_code="AUDIT_SESSION_CLOSE_FAILED",
                context={"session_id": session_id}
            )
    
    async def open_session(
        self,
        session_id: str,
        user_id: str,
        session_summary: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuditSession:
        """Open a closed audit session."""
        try:
            # Create update data to close the session
            update_data = AuditSessionUpdate(
                is_active=True,
                ended_at=None,
                session_summary=session_summary
            )
            
            # Update the session
            return await self.update_session(
                session_id=session_id,
                update_data=update_data,
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
        except Exception as e:
            logger.error(f"Failed to open audit session {session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to open audit session",
                error_code="AUDIT_SESSION_OPEN_FAILED",
                context={"session_id": session_id}
            )

    # --- PDF ingestion relationship helpers ---
    async def add_pdf_ingestion_to_session(
        self,
        session_id: str,
        pdf_ingestion_id: str,
        added_by: str,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Associate a PDF ingestion with an audit session (relationship row)."""
        try:
            supabase = create_supabase_client()
            payload = {
                "id": str(__import__("uuid").uuid4()),
                "audit_session_id": str(session_id),
                "pdf_ingestion_id": str(pdf_ingestion_id),
                "added_at": datetime.now(timezone.utc).isoformat(),
                "added_by": str(added_by),
                "notes": notes,
            }
            res = (
                supabase
                .table(settings.supabase_table_audit_session_pdf_ingestions)
                .insert(payload)
                .execute()
            )
            data = getattr(res, "data", None) or []
            if not data:
                raise BusinessLogicException(
                    detail="Failed to link PDF ingestion to audit session",
                    error_code="AUDIT_SESSION_RELATIONSHIP_CREATE_FAILED",
                    context={"session_id": session_id, "pdf_ingestion_id": pdf_ingestion_id},
                )
            return dict(data[0])
        except BusinessLogicException:
            raise
        except Exception as e:
            logger.error(
                f"add_pdf_ingestion_to_session failed for session {session_id}: {e}",
                exc_info=True,
            )
            raise BusinessLogicException(
                detail="Failed to link PDF ingestion to audit session",
                error_code="AUDIT_SESSION_RELATIONSHIP_CREATE_FAILED",
                context={"session_id": session_id, "pdf_ingestion_id": pdf_ingestion_id},
            )

    async def get_pdf_ingestions_for_session(
        self,
        session_id: str,
        skip: int = 0,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Return ingestions linked to a session with relationship metadata merged."""
        try:
            supabase = create_supabase_client()
            rel_res = (
                supabase
                .table(settings.supabase_table_audit_session_pdf_ingestions)
                .select("*")
                .eq("audit_session_id", str(session_id))
                .order("added_at", desc=True)
                .range(skip, max(skip, skip + limit - 1))
                .execute()
            )
            relationships = list((getattr(rel_res, "data", None) or []))
            if not relationships:
                return []

            ingestion_ids = [r.get("pdf_ingestion_id") for r in relationships if r.get("pdf_ingestion_id")]
            if not ingestion_ids:
                return []

            ing_res = (
                supabase
                .table(settings.supabase_table_pdf_ingestion)
                .select("*")
                .in_("id", ingestion_ids)
                .execute()
            )
            ing_by_id = {row.get("id"): row for row in ((getattr(ing_res, "data", None) or []))}

            merged: List[Dict[str, Any]] = []
            for rel in relationships:
                ing = ing_by_id.get(rel.get("pdf_ingestion_id"))
                if not ing:
                    continue
                item = dict(ing)
                item.update(
                    relationship_id=rel.get("id"),
                    added_at=rel.get("added_at"),
                    added_by=rel.get("added_by"),
                    notes=rel.get("notes"),
                )
                merged.append(item)
            return merged
        except Exception as e:
            logger.error(
                f"get_pdf_ingestions_for_session failed for session {session_id}: {e}",
                exc_info=True,
            )
            raise BusinessLogicException(
                detail="Failed to list session PDF ingestions",
                error_code="AUDIT_SESSION_RELATIONSHIP_LIST_FAILED",
                context={"session_id": session_id},
            )

    async def remove_pdf_ingestion_from_session(
        self,
        session_id: str,
        pdf_ingestion_id: str,
    ) -> Dict[str, Any]:
        """Remove the relationship row linking a PDF to an audit session."""
        try:
            supabase = create_supabase_client()
            res = (
                supabase
                .table(settings.supabase_table_audit_session_pdf_ingestions)
                .delete()
                .eq("audit_session_id", str(session_id))
                .eq("pdf_ingestion_id", str(pdf_ingestion_id))
                .execute()
            )
            deleted = list((getattr(res, "data", None) or []))
            return {
                "removed_count": len(deleted),
                "audit_session_id": str(session_id),
                "pdf_ingestion_id": str(pdf_ingestion_id),
            }
        except Exception as e:
            logger.error(
                f"remove_pdf_ingestion_from_session failed for session {session_id}: {e}",
                exc_info=True,
            )
            raise BusinessLogicException(
                detail="Failed to unlink PDF ingestion from audit session",
                error_code="AUDIT_SESSION_RELATIONSHIP_DELETE_FAILED",
                context={"session_id": session_id, "pdf_ingestion_id": pdf_ingestion_id},
            )

# Factory function
def create_audit_session_service(
    audit_session_repository: AuditSessionRepository,
    user_repository: UserRepository
) -> AuditSessionService:
    """Factory function to create AuditSessionService instance."""
    return AuditSessionService(audit_session_repository, user_repository)
