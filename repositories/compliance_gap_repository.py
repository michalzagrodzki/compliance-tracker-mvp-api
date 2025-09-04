"""
ComplianceGap repository implementation using Supabase.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
from decimal import Decimal
from uuid import UUID

from repositories.base import SupabaseRepository
from entities.compliance_gap import (
    ComplianceGap, 
    ComplianceGapCreate, 
    ComplianceGapUpdate, 
    ComplianceGapFilter,
    GapStatus,
)
from common.exceptions import (
    ResourceNotFoundException,
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

    def _sanitize_for_json(self, value):
        """Recursively convert non-JSON-serializable types to JSON-safe values.

        - Decimal -> float
        - datetime -> ISO string
        - UUID -> str
        - dict/list/tuple/set -> recurse
        """
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Decimal):
            # Convert Decimal to float for JSON/DB numeric
            return float(value)
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, dict):
            return {k: self._sanitize_for_json(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self._sanitize_for_json(v) for v in value]
        return value

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
            # Ensure array columns have sensible defaults if omitted
            if "related_documents" not in gap_data or gap_data["related_documents"] is None:
                gap_data["related_documents"] = []
            if "recommended_actions" not in gap_data or gap_data["recommended_actions"] is None:
                gap_data["recommended_actions"] = []

            gap_data = self._sanitize_for_json(gap_data)
            
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
            update_dict = self._sanitize_for_json(update_dict)
            
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
            if status == GapStatus.ACKNOWLEDGED:
                update_data["acknowledged_at"] = now
            elif status in (GapStatus.RESOLVED, GapStatus.FALSE_POSITIVE, GapStatus.ACCEPTED_RISK):
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
