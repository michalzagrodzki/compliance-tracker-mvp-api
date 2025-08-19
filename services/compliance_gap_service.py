"""
ComplianceGap service using Repository pattern.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from entities.compliance_gap import (
    ComplianceGap, 
    ComplianceGapCreate, 
    ComplianceGapUpdate, 
    ComplianceGapFilter,
    GapStatus,
)
from repositories.compliance_gap_repository import ComplianceGapRepository
from repositories.user_repository import UserRepository
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException,
    AuthorizationException
)
from common.logging import get_logger, log_business_event, log_performance

logger = get_logger("compliance_gap_service")


class ComplianceGapService:
    """
    ComplianceGap service using Repository pattern.
    Handles business logic for compliance gap management.
    """

    def __init__(self, compliance_gap_repository: ComplianceGapRepository, user_repository: UserRepository):
        self.gap_repository = compliance_gap_repository
        self.user_repository = user_repository

    async def create_gap(
        self, 
        gap_create: ComplianceGapCreate, 
        user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> ComplianceGap:
        """Create a new compliance gap."""
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
            
            # Check if user has access to the compliance domain
            if not user.can_access_domain(gap_create.compliance_domain):
                raise AuthorizationException(
                    detail=f"User does not have access to compliance domain: {gap_create.compliance_domain}",
                    error_code="DOMAIN_ACCESS_DENIED"
                )
            
            # Add audit information
            gap_create.ip_address = ip_address
            gap_create.user_agent = user_agent
            
            # Create the gap
            created_gap = await self.gap_repository.create(gap_create)
            
            # Log business event
            log_business_event(
                event_type="COMPLIANCE_GAP_CREATED",
                entity_type="compliance_gap",
                entity_id=created_gap.id,
                action="create",
                user_id=user_id,
                details={
                    "compliance_domain": created_gap.compliance_domain,
                    "gap_type": created_gap.gap_type.value,
                    "risk_level": created_gap.risk_level.value,
                    "audit_session_id": created_gap.audit_session_id
                }
            )
            
            # Log performance
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="create_compliance_gap",
                duration_ms=duration_ms,
                success=True,
                item_count=1
            )
            
            return created_gap
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to create compliance gap: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create compliance gap",
                error_code="COMPLIANCE_GAP_CREATION_FAILED",
                context={"gap_title": gap_create.gap_title}
            )

    async def get_gap_by_id(self, gap_id: str, user_id: str) -> ComplianceGap:
        """Get a compliance gap by ID with access control."""
        try:
            # Get the gap
            gap = await self.gap_repository.get_by_id(gap_id)
            if not gap:
                raise ResourceNotFoundException(
                    resource_type="ComplianceGap",
                    resource_id=gap_id
                )
            
            # Check user access to the compliance domain
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            # Allow access if user is admin or has domain access
            if not (user.is_admin() or user.can_access_domain(gap.compliance_domain)):
                raise AuthorizationException(
                    detail=f"Access denied to compliance domain: {gap.compliance_domain}",
                    error_code="DOMAIN_ACCESS_DENIED"
                )
            
            return gap
            
        except (ResourceNotFoundException, ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to get compliance gap {gap_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gap",
                error_code="COMPLIANCE_GAP_RETRIEVAL_FAILED",
                context={"gap_id": gap_id}
            )

    async def update_gap(self, gap_id: str, gap_update: ComplianceGapUpdate, user_id: str) -> ComplianceGap:
        """Update a compliance gap."""
        try:
            # Get existing gap and validate access
            gap = await self.get_gap_by_id(gap_id, user_id)
            
            # Update the gap
            updated_gap = await self.gap_repository.update(gap_id, gap_update)
            if not updated_gap:
                raise ResourceNotFoundException(
                    resource_type="ComplianceGap",
                    resource_id=gap_id
                )
            
            # Log business event
            log_business_event(
                event_type="COMPLIANCE_GAP_UPDATED",
                entity_type="compliance_gap",
                entity_id=gap_id,
                action="update",
                user_id=user_id,
                details={"updated_fields": list(gap_update.model_dump(exclude_none=True).keys())}
            )
            
            return updated_gap
            
        except (ResourceNotFoundException, ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to update compliance gap {gap_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update compliance gap",
                error_code="COMPLIANCE_GAP_UPDATE_FAILED",
                context={"gap_id": gap_id}
            )

    async def update_gap_status(self, gap_id: str, status: GapStatus, user_id: str, notes: Optional[str] = None) -> ComplianceGap:
        """Update compliance gap status."""
        try:
            # Get existing gap and validate access
            gap = await self.get_gap_by_id(gap_id, user_id)
            
            # Validate status transition
            self._validate_status_transition(gap.status, status)
            
            # Update the status
            updated_gap = await self.gap_repository.update_status(gap_id, status, user_id, notes)
            if not updated_gap:
                raise ResourceNotFoundException(
                    resource_type="ComplianceGap",
                    resource_id=gap_id
                )
            
            # Log business event
            log_business_event(
                event_type="COMPLIANCE_GAP_STATUS_UPDATED",
                entity_type="compliance_gap",
                entity_id=gap_id,
                action="update",
                user_id=user_id,
                details={
                    "old_status": gap.status.value,
                    "new_status": status.value,
                    "has_notes": bool(notes)
                }
            )
            
            return updated_gap
            
        except (ResourceNotFoundException, ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to update compliance gap status {gap_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update compliance gap status",
                error_code="COMPLIANCE_GAP_STATUS_UPDATE_FAILED",
                context={"gap_id": gap_id, "status": status.value}
            )

    async def assign_gap(
        self, 
        gap_id: str, 
        assigned_user_id: str, 
        assigner_user_id: str,
        due_date: Optional[datetime] = None
    ) -> ComplianceGap:
        """Assign a compliance gap to a user."""
        try:
            # Get existing gap and validate access
            gap = await self.get_gap_by_id(gap_id, assigner_user_id)
            
            # Validate assigned user exists and has domain access
            assigned_user = await self.user_repository.get_by_id(assigned_user_id)
            if not assigned_user or not assigned_user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive assigned user",
                    field="assigned_user_id",
                    value=assigned_user_id
                )
            
            if not assigned_user.can_access_domain(gap.compliance_domain):
                raise ValidationException(
                    detail=f"Assigned user does not have access to compliance domain: {gap.compliance_domain}",
                    field="assigned_user_id",
                    value=assigned_user_id
                )
            
            # Assign the gap
            updated_gap = await self.gap_repository.assign_to_user(gap_id, assigned_user_id, assigner_user_id, due_date)
            if not updated_gap:
                raise ResourceNotFoundException(
                    resource_type="ComplianceGap",
                    resource_id=gap_id
                )
            
            # Log business event
            log_business_event(
                event_type="COMPLIANCE_GAP_ASSIGNED",
                entity_type="compliance_gap",
                entity_id=gap_id,
                action="assign",
                user_id=assigner_user_id,
                details={
                    "assigned_to": assigned_user_id,
                    "due_date": due_date.isoformat() if due_date else None,
                    "assigned_user_email": assigned_user.email
                }
            )
            
            return updated_gap
            
        except (ResourceNotFoundException, ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to assign compliance gap {gap_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to assign compliance gap",
                error_code="COMPLIANCE_GAP_ASSIGNMENT_FAILED",
                context={"gap_id": gap_id, "assigned_user_id": assigned_user_id}
            )

    async def mark_gap_reviewed(self, gap_id: str, reviewer_user_id: str) -> ComplianceGap:
        """Mark a compliance gap as reviewed."""
        try:
            # Get existing gap and validate access
            gap = await self.get_gap_by_id(gap_id, reviewer_user_id)
            
            # Mark as reviewed
            updated_gap = await self.gap_repository.mark_reviewed(gap_id, reviewer_user_id)
            if not updated_gap:
                raise ResourceNotFoundException(
                    resource_type="ComplianceGap",
                    resource_id=gap_id
                )
            
            # Log business event
            log_business_event(
                event_type="COMPLIANCE_GAP_REVIEWED",
                entity_type="compliance_gap",
                entity_id=gap_id,
                action="review",
                user_id=reviewer_user_id
            )
            
            return updated_gap
            
        except (ResourceNotFoundException, ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to mark compliance gap as reviewed {gap_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to mark compliance gap as reviewed",
                error_code="COMPLIANCE_GAP_REVIEW_FAILED",
                context={"gap_id": gap_id}
            )

    async def list_gaps(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[ComplianceGapFilter] = None
    ) -> List[ComplianceGap]:
        """List compliance gaps with access control."""
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
                if not filters:
                    filters = ComplianceGapFilter()
                
                # If a specific domain is requested, check access
                if filters.compliance_domain and not user.can_access_domain(filters.compliance_domain):
                    raise AuthorizationException(
                        detail=f"Access denied to compliance domain: {filters.compliance_domain}",
                        error_code="DOMAIN_ACCESS_DENIED"
                    )
                
                # If no specific domain is requested, limit to user's domains
                if not filters.compliance_domain:
                    # Use repository method to filter by user's domains
                    gaps = await self.gap_repository.get_by_domains(user.compliance_domains, skip, limit)
                else:
                    gaps = await self.gap_repository.list(skip, limit, filters)
            else:
                # Admin can see all gaps
                gaps = await self.gap_repository.list(skip, limit, filters)
            
            # Log performance
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="list_compliance_gaps",
                duration_ms=duration_ms,
                success=True,
                item_count=len(gaps)
            )
            
            return gaps
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to list compliance gaps: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gaps",
                error_code="COMPLIANCE_GAP_LIST_FAILED"
            )

    async def get_gaps_by_audit_session(self, audit_session_id: str, user_id: str) -> List[ComplianceGap]:
        """Get compliance gaps by audit session with access control."""
        try:
            # Get all gaps for the audit session
            gaps = await self.gap_repository.get_by_audit_session(audit_session_id)
            
            # Filter by user's accessible domains if not admin
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            if not user.is_admin():
                gaps = [gap for gap in gaps if user.can_access_domain(gap.compliance_domain)]
            
            return gaps
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to get compliance gaps by audit session {audit_session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gaps by audit session",
                error_code="COMPLIANCE_GAP_AUDIT_SESSION_RETRIEVAL_FAILED",
                context={"audit_session_id": audit_session_id}
            )

    async def get_gaps_by_domain(self, domain: str, user_id: str, skip: int = 0, limit: int = 100) -> List[ComplianceGap]:
        """Get compliance gaps by compliance domain with access control."""
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
                    detail=f"Access denied to compliance domain: {domain}",
                    error_code="DOMAIN_ACCESS_DENIED"
                )
            
            return await self.gap_repository.get_by_compliance_domain(domain, skip, limit)
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to get compliance gaps by domain {domain}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gaps by domain",
                error_code="COMPLIANCE_GAP_DOMAIN_RETRIEVAL_FAILED",
                context={"domain": domain}
            )

    async def get_gaps_by_user_involvement(self, target_user_id: str, requesting_user_id: str, skip: int = 0, limit: int = 100) -> List[ComplianceGap]:
        """Get compliance gaps where a user is involved (created or assigned) with access control."""
        try:
            # Validate requesting user
            requesting_user = await self.user_repository.get_by_id(requesting_user_id)
            if not requesting_user:
                raise ValidationException(
                    detail="Invalid requesting user",
                    field="requesting_user_id",
                    value=requesting_user_id
                )
            
            # Non-admin users can only see their own gaps
            if not requesting_user.is_admin() and target_user_id != requesting_user_id:
                raise AuthorizationException(
                    detail="Access denied to other user's gaps",
                    error_code="USER_ACCESS_DENIED"
                )
            
            gaps = await self.gap_repository.get_by_user(target_user_id, skip, limit)
            
            # Filter by accessible domains if not admin
            if not requesting_user.is_admin():
                gaps = [gap for gap in gaps if requesting_user.can_access_domain(gap.compliance_domain)]
            
            return gaps
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to get compliance gaps by user {target_user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gaps by user",
                error_code="COMPLIANCE_GAP_USER_RETRIEVAL_FAILED",
                context={"target_user_id": target_user_id}
            )

    async def get_gap_statistics(self, user_id: str, compliance_domain: Optional[str] = None) -> Dict[str, Any]:
        """Get compliance gap statistics with access control."""
        try:
            # Validate user access
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            # If domain is specified, check access
            if compliance_domain and not (user.is_admin() or user.can_access_domain(compliance_domain)):
                raise AuthorizationException(
                    detail=f"Access denied to compliance domain: {compliance_domain}",
                    error_code="DOMAIN_ACCESS_DENIED"
                )
            
            return await self.gap_repository.get_statistics(compliance_domain)
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to get compliance gap statistics: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gap statistics",
                error_code="COMPLIANCE_GAP_STATISTICS_FAILED",
                context={"compliance_domain": compliance_domain}
            )

    async def get_overdue_gaps(self, user_id: str, skip: int = 0, limit: int = 100) -> List[ComplianceGap]:
        """Get overdue compliance gaps with access control."""
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            gaps = await self.gap_repository.get_overdue_gaps(skip, limit)
            
            # Filter by accessible domains if not admin
            if not user.is_admin():
                gaps = [gap for gap in gaps if user.can_access_domain(gap.compliance_domain)]
            
            return gaps
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to get overdue compliance gaps: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve overdue compliance gaps",
                error_code="COMPLIANCE_GAP_OVERDUE_RETRIEVAL_FAILED"
            )

    def _validate_status_transition(self, current_status: GapStatus, new_status: GapStatus) -> None:
        """Validate that a status transition is allowed."""
        # Define allowed transitions
        allowed_transitions = {
            GapStatus.IDENTIFIED: [GapStatus.ACKNOWLEDGED, GapStatus.FALSE_POSITIVE],
            GapStatus.ACKNOWLEDGED: [GapStatus.IN_PROGRESS, GapStatus.FALSE_POSITIVE, GapStatus.ACCEPTED_RISK],
            GapStatus.IN_PROGRESS: [GapStatus.RESOLVED, GapStatus.ACKNOWLEDGED, GapStatus.ACCEPTED_RISK],
            GapStatus.RESOLVED: [GapStatus.IN_PROGRESS],  # Can reopen if needed
            GapStatus.FALSE_POSITIVE: [GapStatus.IDENTIFIED],  # Can revert if mistake
            GapStatus.ACCEPTED_RISK: [GapStatus.IN_PROGRESS]  # Can decide to address later
        }
        
        if new_status not in allowed_transitions.get(current_status, []):
            raise ValidationException(
                detail=f"Invalid status transition from {current_status.value} to {new_status.value}",
                field="status",
                value=new_status.value
            )


# Factory function
def create_compliance_gap_service(
    compliance_gap_repository: ComplianceGapRepository,
    user_repository: UserRepository
) -> ComplianceGapService:
    """Factory function to create ComplianceGapService instance."""
    return ComplianceGapService(compliance_gap_repository, user_repository)