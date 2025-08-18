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

    async def create(self, entity: DocumentChunk) -> DocumentChunk:
        try:
            data = entity.to_dict()
            data = self._add_audit_fields(data, is_update=False)
            res = self.supabase.table(self.table_name).insert(data).execute()
            return DocumentChunk.from_dict(res.data[0])
        except Exception as e:
            logger.error(f"Failed to create document: {e}", exc_info=True)
            raise BusinessLogicException(detail="Failed to create document", error_code="DOCUMENT_CREATE_FAILED")

    async def get_by_id(self, entity_id: str) -> Optional[DocumentChunk]:
        try:
            res = self.supabase.table(self.table_name).select("*").eq("id", entity_id).execute()
            if not res.data:
                return None
            return DocumentChunk.from_dict(res.data[0])
        except Exception as e:
            logger.error(f"Failed to get document {entity_id}: {e}", exc_info=True)
            raise BusinessLogicException(detail="Failed to retrieve document", error_code="DOCUMENT_GET_FAILED")

    async def update(self, entity_id: str, update_data: Dict[str, Any]) -> Optional[DocumentChunk]:
        try:
            update_data = self._add_audit_fields(update_data, is_update=True)
            res = self.supabase.table(self.table_name).update(update_data).eq("id", entity_id).execute()
            if not res.data:
                return None
            return DocumentChunk.from_dict(res.data[0])
        except Exception as e:
            logger.error(f"Failed to update document {entity_id}: {e}", exc_info=True)
            raise BusinessLogicException(detail="Failed to update document", error_code="DOCUMENT_UPDATE_FAILED")

    async def delete(self, entity_id: str) -> bool:
        try:
            res = self.supabase.table(self.table_name).delete().eq("id", entity_id).execute()
            return bool(res.data)
        except Exception as e:
            logger.error(f"Failed to delete document {entity_id}: {e}", exc_info=True)
            raise BusinessLogicException(detail="Failed to delete document", error_code="DOCUMENT_DELETE_FAILED")

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

    async def list_by_source_filename(self, source_filename: str) -> List[DocumentChunk]:
        try:
            res = (
                self.supabase.table(self.table_name)
                .select("*")
                .eq("source_filename", source_filename)
                .order("chunk_index", desc=False)
                .execute()
            )
            return [DocumentChunk.from_dict(r) for r in res.data]
        except Exception as e:
            logger.error(f"Failed to list by source filename {source_filename}: {e}")
            raise BusinessLogicException(detail="Failed to fetch by source filename", error_code="DOCUMENT_SOURCE_FAILED")

    async def list_by_domain(self, domain: str, skip: int = 0, limit: int = 100) -> List[DocumentChunk]:
        try:
            res = (
                self.supabase.table(self.table_name)
                .select("*")
                .eq("compliance_domain", domain)
                .order("created_at", desc=True)
                .range(skip, skip + limit - 1)
                .execute()
            )
            return [DocumentChunk.from_dict(r) for r in res.data]
        except Exception as e:
            logger.error(f"Failed to list by domain {domain}: {e}")
            raise BusinessLogicException(detail="Failed to fetch by domain", error_code="DOCUMENT_DOMAIN_FAILED")

    async def list_by_version(self, version: str, skip: int = 0, limit: int = 100) -> List[DocumentChunk]:
        try:
            res = (
                self.supabase.table(self.table_name)
                .select("*")
                .eq("document_version", version)
                .order("compliance_domain", desc=False)
                .range(skip, skip + limit - 1)
                .execute()
            )
            return [DocumentChunk.from_dict(r) for r in res.data]
        except Exception as e:
            logger.error(f"Failed to list by version {version}: {e}")
            raise BusinessLogicException(detail="Failed to fetch by version", error_code="DOCUMENT_VERSION_FAILED")

    async def list_by_domain_and_version(self, domain: str, version: str, skip: int = 0, limit: int = 100) -> List[DocumentChunk]:
        try:
            res = (
                self.supabase.table(self.table_name)
                .select("*")
                .eq("compliance_domain", domain)
                .eq("document_version", version)
                .order("source_filename", desc=False)
                .range(skip, skip + limit - 1)
                .execute()
            )
            return [DocumentChunk.from_dict(r) for r in res.data]
        except Exception as e:
            logger.error(f"Failed to list by domain+version ({domain}, {version}): {e}")
            raise BusinessLogicException(detail="Failed to fetch by domain and version", error_code="DOCUMENT_DOMAIN_VERSION_FAILED")

    async def list_by_tags(
        self, tags: List[str], match_mode: str = "any", compliance_domain: Optional[str] = None, skip: int = 0, limit: int = 100
    ) -> List[DocumentChunk]:
        try:
            q = self.supabase.table(self.table_name).select("*")
            if compliance_domain:
                q = q.eq("compliance_domain", compliance_domain)

            m = (match_mode or "any").lower()
            if m == "all":
                q = q.contains("document_tags", tags)
            elif m == "exact":
                for t in tags:
                    q = q.contains("document_tags", [t])
            else:
                q = q.overlaps("document_tags", tags)

            res = q.order("created_at", desc=True).range(skip, skip + limit - 1).execute()
            return [DocumentChunk.from_dict(r) for r in res.data]
        except Exception as e:
            logger.error(f"Failed to list by tags {tags}: {e}")
            raise BusinessLogicException(detail="Failed to fetch by tags", error_code="DOCUMENT_TAGS_FAILED")
