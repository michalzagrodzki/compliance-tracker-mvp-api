"""
Document repository implementation using Supabase.
"""

from typing import Optional, List, Dict, Any

from repositories.base import SupabaseRepository
from entities.document import DocumentChunk, DocumentFilter
from common.exceptions import BusinessLogicException
from common.logging import get_logger

logger = get_logger("document_repository")

class DocumentRepository(SupabaseRepository[DocumentChunk]):
    """Repository for DocumentChunk operations with Supabase."""

    def __init__(self, supabase_client, table_name: str = "documents"):
        super().__init__(supabase_client, table_name)

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[DocumentFilter] = None,
        order_by: Optional[str] = None,
    ) -> List[DocumentChunk]:
        try:
            q = self.supabase.table(self.table_name).select("*")

            if filters:
                simple_filters: Dict[str, Any] = {}
                if filters.compliance_domain is not None:
                    simple_filters["compliance_domain"] = filters.compliance_domain
                if filters.approval_status is not None:
                    simple_filters["approval_status"] = filters.approval_status
                if filters.uploaded_by is not None:
                    simple_filters["uploaded_by"] = filters.uploaded_by
                if filters.approved_by is not None:
                    simple_filters["approved_by"] = filters.approved_by

                q = self._build_filters(q, simple_filters)

                if filters.document_version is not None:
                    q = q.ilike("document_version", f"%{filters.document_version}%")
                if filters.source_filename is not None:
                    q = q.ilike("source_filename", f"%{filters.source_filename}%")

                if filters.created_after is not None:
                    q = q.gte("created_at", filters.created_after.isoformat())
                if filters.created_before is not None:
                    q = q.lte("created_at", filters.created_before.isoformat())

                if filters.document_tags:
                    mode = (filters.tags_match_mode or "any").lower()
                    if mode == "all":
                        q = q.contains("document_tags", filters.document_tags)
                    elif mode == "exact":
                        q = q.eq("document_tags", filters.document_tags)
                    else:
                        q = q.overlaps("document_tags", filters.document_tags)

            q = self._apply_ordering(q, order_by or "-created_at").range(skip, skip + limit - 1)
            res = q.execute()
            return [DocumentChunk.from_dict(r) for r in res.data]
        except Exception as e:
            logger.error(f"Failed to list documents: {e}", exc_info=True)
            raise BusinessLogicException(detail="Failed to list documents", error_code="DOCUMENT_LIST_FAILED")

    async def count(self, filters: Optional[DocumentFilter] = None) -> int:
        """Count documents matching the same filters used in list()."""
        try:
            q = self.supabase.table(self.table_name).select("id", count="exact")

            if filters:
                simple_filters: Dict[str, Any] = {}
                if filters.compliance_domain is not None:
                    simple_filters["compliance_domain"] = filters.compliance_domain
                if filters.approval_status is not None:
                    simple_filters["approval_status"] = filters.approval_status
                if filters.uploaded_by is not None:
                    simple_filters["uploaded_by"] = filters.uploaded_by
                if filters.approved_by is not None:
                    simple_filters["approved_by"] = filters.approved_by

                q = self._build_filters(q, simple_filters)

                if filters.document_version is not None:
                    q = q.ilike("document_version", f"%{filters.document_version}%")
                if filters.source_filename is not None:
                    q = q.ilike("source_filename", f"%{filters.source_filename}%")

                if filters.created_after is not None:
                    q = q.gte("created_at", filters.created_after.isoformat())
                if filters.created_before is not None:
                    q = q.lte("created_at", filters.created_before.isoformat())

                if filters.document_tags:
                    mode = (filters.tags_match_mode or "any").lower()
                    if mode == "all":
                        q = q.contains("document_tags", filters.document_tags)
                    elif mode == "exact":
                        q = q.eq("document_tags", filters.document_tags)
                    else:
                        q = q.overlaps("document_tags", filters.document_tags)

            res = q.execute()
            return int(getattr(res, "count", 0) or 0)
        except Exception:
            return 0

