"""
ComplianceGap repository implementation using Supabase.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
import uuid

from repositories.base import SupabaseRepository
from entities.compliance_gap import (
    ComplianceGap, 
    ComplianceGapCreate, 
    ComplianceGapUpdate, 
    ComplianceGapFilter,
    GapStatus,
    RiskLevel,
    BusinessImpact
)
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException
)
from common.logging import get_logger

logger = get_logger("compliance_gap_repository")


class ComplianceGapRepository(SupabaseRepository[ComplianceGap]):
    """
    Repository for ComplianceGap entity operations with Supabase.
    """

    def __init__(self, supabase_client, table_name: str = "compliance_gaps"):
        super().__init__(supabase_client, table_name)

    async def create(self, gap_create: ComplianceGapCreate) -> ComplianceGap:
        """Create a new compliance gap."""
        try:
            # Generate ID and timestamps
            gap_id = str(uuid.uuid4())
            now = datetime.utcnow()
            
            # Convert to dict and add required fields
            gap_data = gap_create.model_dump()
            gap_data.update({
                "id": gap_id,
                "status": GapStatus.IDENTIFIED.value,
                "detected_at": now.isoformat(),
                "created_at": now.isoformat(),
                "updated_at": now.isoformat(),
                "auto_generated": True
            })
            
            # Insert into database
            result = self.supabase.table(self.table_name).insert(gap_data).execute()
            
            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to create compliance gap",
                    error_code="COMPLIANCE_GAP_CREATION_FAILED"
                )
            
            # Convert back to ComplianceGap entity
            created_gap = ComplianceGap.from_dict(result.data[0])
            
            logger.info(f"Created compliance gap: {created_gap.gap_title} (ID: {created_gap.id})")
            return created_gap
            
        except Exception as e:
            logger.error(f"Failed to create compliance gap: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create compliance gap",
                error_code="COMPLIANCE_GAP_CREATION_FAILED",
                context={"gap_title": gap_create.gap_title}
            )

    async def get_by_id(self, gap_id: str) -> Optional[ComplianceGap]:
        """Retrieve a compliance gap by ID."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("id", gap_id)\
                .execute()
            
            if not result.data:
                return None
            
            return ComplianceGap.from_dict(result.data[0])
            
        except Exception as e:
            logger.error(f"Failed to get compliance gap by ID {gap_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gap",
                error_code="COMPLIANCE_GAP_RETRIEVAL_FAILED",
                context={"gap_id": gap_id}
            )

    async def update(self, gap_id: str, update_data: ComplianceGapUpdate) -> Optional[ComplianceGap]:
        """Update a compliance gap by ID."""
        try:
            # Check if gap exists
            if not await self.exists(gap_id):
                raise ResourceNotFoundException(
                    resource_type="ComplianceGap",
                    resource_id=gap_id
                )
            
            # Convert update data to dict, excluding None values
            update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
            
            if not update_dict:
                # No changes to apply
                return await self.get_by_id(gap_id)
            
            # Add updated timestamp
            update_dict["updated_at"] = datetime.utcnow().isoformat()
            
            # Update in database
            result = self.supabase.table(self.table_name)\
                .update(update_dict)\
                .eq("id", gap_id)\
                .execute()
            
            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to update compliance gap",
                    error_code="COMPLIANCE_GAP_UPDATE_FAILED"
                )
            
            updated_gap = ComplianceGap.from_dict(result.data[0])
            logger.info(f"Updated compliance gap: {updated_gap.gap_title} (ID: {gap_id})")
            return updated_gap
            
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Failed to update compliance gap {gap_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update compliance gap",
                error_code="COMPLIANCE_GAP_UPDATE_FAILED",
                context={"gap_id": gap_id}
            )

    async def delete(self, gap_id: str) -> bool:
        """Delete a compliance gap by ID (hard delete in this case)."""
        try:
            result = self.supabase.table(self.table_name)\
                .delete()\
                .eq("id", gap_id)\
                .execute()
            
            if result.data:
                logger.info(f"Deleted compliance gap: {gap_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete compliance gap {gap_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to delete compliance gap",
                error_code="COMPLIANCE_GAP_DELETION_FAILED",
                context={"gap_id": gap_id}
            )

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[ComplianceGapFilter] = None,
        order_by: Optional[str] = None
    ) -> List[ComplianceGap]:
        """List compliance gaps with optional filtering and pagination."""
        try:
            query = self.supabase.table(self.table_name).select("*")
            
            # Apply filters
            if filters:
                filter_dict = {}
                for field, value in filters.model_dump().items():
                    if value is not None:
                        if field == "is_overdue":
                            # Handle special overdue filter
                            if value:
                                # Find gaps with due_date in the past and not resolved
                                now = datetime.utcnow().isoformat()
                                query = query.lt("due_date", now).neq("status", "resolved")
                        else:
                            filter_dict[field] = value
                
                query = self._build_filters(query, filter_dict)
            
            # Apply ordering (default to detected_at desc)
            query = self._apply_ordering(query, order_by or "-detected_at")
            
            # Apply pagination
            query = query.range(skip, skip + limit - 1)
            
            result = query.execute()
            
            # Convert to ComplianceGap entities
            gaps = [ComplianceGap.from_dict(gap_data) for gap_data in result.data]
            
            logger.debug(f"Listed {len(gaps)} compliance gaps with filters: {filters}")
            return gaps
            
        except Exception as e:
            logger.error(f"Failed to list compliance gaps: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gaps",
                error_code="COMPLIANCE_GAP_LIST_FAILED"
            )

    async def get_by_audit_session(self, audit_session_id: str) -> List[ComplianceGap]:
        """Get all compliance gaps for a specific audit session."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("audit_session_id", audit_session_id)\
                .order("detected_at", desc=True)\
                .execute()
            
            gaps = [ComplianceGap.from_dict(gap_data) for gap_data in result.data]
            
            logger.debug(f"Found {len(gaps)} compliance gaps for audit session: {audit_session_id}")
            return gaps
            
        except Exception as e:
            logger.error(f"Failed to get compliance gaps by audit session {audit_session_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gaps by audit session",
                error_code="COMPLIANCE_GAP_AUDIT_SESSION_RETRIEVAL_FAILED",
                context={"audit_session_id": audit_session_id}
            )

    async def get_by_compliance_domain(self, domain: str, skip: int = 0, limit: int = 100) -> List[ComplianceGap]:
        """Get all compliance gaps for a specific compliance domain."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("compliance_domain", domain)\
                .order("detected_at", desc=True)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            gaps = [ComplianceGap.from_dict(gap_data) for gap_data in result.data]
            
            logger.debug(f"Found {len(gaps)} compliance gaps for domain: {domain}")
            return gaps
            
        except Exception as e:
            logger.error(f"Failed to get compliance gaps by domain {domain}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gaps by domain",
                error_code="COMPLIANCE_GAP_DOMAIN_RETRIEVAL_FAILED",
                context={"domain": domain}
            )

    async def get_by_user(self, user_id: str, skip: int = 0, limit: int = 100) -> List[ComplianceGap]:
        """Get all compliance gaps created by or assigned to a user."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .or_(f"user_id.eq.{user_id},assigned_to.eq.{user_id}")\
                .order("detected_at", desc=True)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            gaps = [ComplianceGap.from_dict(gap_data) for gap_data in result.data]
            
            logger.debug(f"Found {len(gaps)} compliance gaps for user: {user_id}")
            return gaps
            
        except Exception as e:
            logger.error(f"Failed to get compliance gaps by user {user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gaps by user",
                error_code="COMPLIANCE_GAP_USER_RETRIEVAL_FAILED",
                context={"user_id": user_id}
            )

    async def get_by_domains(self, domains: List[str], skip: int = 0, limit: int = 100) -> List[ComplianceGap]:
        """Get all compliance gaps for multiple compliance domains."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .in_("compliance_domain", domains)\
                .order("detected_at", desc=True)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            gaps = [ComplianceGap.from_dict(gap_data) for gap_data in result.data]
            
            logger.debug(f"Found {len(gaps)} compliance gaps for domains: {domains}")
            return gaps
            
        except Exception as e:
            logger.error(f"Failed to get compliance gaps by domains {domains}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gaps by domains",
                error_code="COMPLIANCE_GAP_DOMAINS_RETRIEVAL_FAILED",
                context={"domains": domains}
            )

    async def update_status(self, gap_id: str, status: GapStatus, user_id: str, notes: Optional[str] = None) -> Optional[ComplianceGap]:
        """Update the status of a compliance gap."""
        try:
            now = datetime.utcnow().isoformat()
            update_data = {
                "status": status.value,
                "updated_at": now
            }
            
            # Add status-specific timestamps
            if status == GapStatus.ACKNOWLEDGED and status != GapStatus.ACKNOWLEDGED:
                update_data["acknowledged_at"] = now
            elif status == GapStatus.RESOLVED:
                update_data["resolved_at"] = now
            elif status == GapStatus.FALSE_POSITIVE:
                update_data["resolved_at"] = now
            elif status == GapStatus.ACCEPTED_RISK:
                update_data["resolved_at"] = now
            
            if notes:
                update_data["resolution_notes"] = notes
            
            result = self.supabase.table(self.table_name)\
                .update(update_data)\
                .eq("id", gap_id)\
                .execute()
            
            if not result.data:
                raise ResourceNotFoundException(
                    resource_type="ComplianceGap",
                    resource_id=gap_id
                )
            
            updated_gap = ComplianceGap.from_dict(result.data[0])
            logger.info(f"Updated status for compliance gap {gap_id} to {status.value}")
            return updated_gap
            
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Failed to update status for compliance gap {gap_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update compliance gap status",
                error_code="COMPLIANCE_GAP_STATUS_UPDATE_FAILED",
                context={"gap_id": gap_id, "status": status.value}
            )

    async def assign_to_user(self, gap_id: str, assigned_user_id: str, assigner_user_id: str, 
                            due_date: Optional[datetime] = None) -> Optional[ComplianceGap]:
        """Assign a compliance gap to a user."""
        try:
            update_data = {
                "assigned_to": assigned_user_id,
                "updated_at": datetime.utcnow().isoformat()
            }
            
            if due_date:
                update_data["due_date"] = due_date.isoformat()
            
            result = self.supabase.table(self.table_name)\
                .update(update_data)\
                .eq("id", gap_id)\
                .execute()
            
            if not result.data:
                raise ResourceNotFoundException(
                    resource_type="ComplianceGap",
                    resource_id=gap_id
                )
            
            updated_gap = ComplianceGap.from_dict(result.data[0])
            logger.info(f"Assigned compliance gap {gap_id} to user {assigned_user_id}")
            return updated_gap
            
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Failed to assign compliance gap {gap_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to assign compliance gap",
                error_code="COMPLIANCE_GAP_ASSIGNMENT_FAILED",
                context={"gap_id": gap_id, "assigned_user_id": assigned_user_id}
            )

    async def mark_reviewed(self, gap_id: str, reviewer_user_id: str) -> Optional[ComplianceGap]:
        """Mark a compliance gap as reviewed."""
        try:
            update_data = {
                "last_reviewed_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat()
            }
            
            result = self.supabase.table(self.table_name)\
                .update(update_data)\
                .eq("id", gap_id)\
                .execute()
            
            if not result.data:
                raise ResourceNotFoundException(
                    resource_type="ComplianceGap",
                    resource_id=gap_id
                )
            
            updated_gap = ComplianceGap.from_dict(result.data[0])
            logger.info(f"Marked compliance gap {gap_id} as reviewed by {reviewer_user_id}")
            return updated_gap
            
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Failed to mark compliance gap {gap_id} as reviewed: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to mark compliance gap as reviewed",
                error_code="COMPLIANCE_GAP_REVIEW_FAILED",
                context={"gap_id": gap_id}
            )

    async def get_statistics(self, compliance_domain: Optional[str] = None) -> Dict[str, Any]:
        """Get statistics about compliance gaps."""
        try:
            base_query = self.supabase.table(self.table_name)
            
            if compliance_domain:
                base_query = base_query.eq("compliance_domain", compliance_domain)
            
            # Get all gaps for statistics
            result = base_query.select("*").execute()
            gaps_data = result.data
            
            if not gaps_data:
                return {
                    "total_gaps": 0,
                    "regulatory_gaps": 0,
                    "total_potential_fines": 0,
                    "avg_confidence_score": 0,
                    "resolution_rate_percent": 0,
                    "status_breakdown": {},
                    "risk_level_breakdown": {},
                    "domain_breakdown": {}
                }
            
            gaps = [ComplianceGap.from_dict(gap_data) for gap_data in gaps_data]
            
            # Calculate statistics
            total_gaps = len(gaps)
            regulatory_gaps = sum(1 for gap in gaps if gap.regulatory_requirement)
            total_potential_fines = sum(gap.potential_fine_amount or 0 for gap in gaps)
            confidence_scores = [gap.confidence_score for gap in gaps if gap.confidence_score]
            avg_confidence_score = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
            resolved_gaps = sum(1 for gap in gaps if gap.is_resolved())
            resolution_rate = (resolved_gaps / total_gaps * 100) if total_gaps > 0 else 0
            
            # Status breakdown
            status_breakdown = {}
            for gap in gaps:
                status = gap.status.value
                status_breakdown[status] = status_breakdown.get(status, 0) + 1
            
            # Risk level breakdown
            risk_level_breakdown = {}
            for gap in gaps:
                risk = gap.risk_level.value
                risk_level_breakdown[risk] = risk_level_breakdown.get(risk, 0) + 1
            
            # Domain breakdown
            domain_breakdown = {}
            for gap in gaps:
                domain = gap.compliance_domain
                domain_breakdown[domain] = domain_breakdown.get(domain, 0) + 1
            
            statistics = {
                "total_gaps": total_gaps,
                "regulatory_gaps": regulatory_gaps,
                "total_potential_fines": float(total_potential_fines),
                "avg_confidence_score": float(avg_confidence_score),
                "resolution_rate_percent": float(resolution_rate),
                "status_breakdown": status_breakdown,
                "risk_level_breakdown": risk_level_breakdown,
                "domain_breakdown": domain_breakdown
            }
            
            logger.debug(f"Generated compliance gap statistics: {statistics}")
            return statistics
            
        except Exception as e:
            logger.error(f"Failed to get compliance gap statistics: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve compliance gap statistics",
                error_code="COMPLIANCE_GAP_STATISTICS_FAILED",
                context={"compliance_domain": compliance_domain}
            )

    async def get_overdue_gaps(self, skip: int = 0, limit: int = 100) -> List[ComplianceGap]:
        """Get all overdue compliance gaps."""
        try:
            now = datetime.utcnow().isoformat()
            
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .lt("due_date", now)\
                .neq("status", "resolved")\
                .neq("status", "false_positive")\
                .neq("status", "accepted_risk")\
                .order("due_date", desc=False)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            gaps = [ComplianceGap.from_dict(gap_data) for gap_data in result.data]
            
            logger.debug(f"Found {len(gaps)} overdue compliance gaps")
            return gaps
            
        except Exception as e:
            logger.error(f"Failed to get overdue compliance gaps: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve overdue compliance gaps",
                error_code="COMPLIANCE_GAP_OVERDUE_RETRIEVAL_FAILED"
            )

    async def get_critical_gaps(self, skip: int = 0, limit: int = 100) -> List[ComplianceGap]:
        """Get all critical compliance gaps."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("risk_level", "critical")\
                .neq("status", "resolved")\
                .neq("status", "false_positive")\
                .neq("status", "accepted_risk")\
                .order("detected_at", desc=True)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            gaps = [ComplianceGap.from_dict(gap_data) for gap_data in result.data]
            
            logger.debug(f"Found {len(gaps)} critical compliance gaps")
            return gaps
            
        except Exception as e:
            logger.error(f"Failed to get critical compliance gaps: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve critical compliance gaps",
                error_code="COMPLIANCE_GAP_CRITICAL_RETRIEVAL_FAILED"
            )