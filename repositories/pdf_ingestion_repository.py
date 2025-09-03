"""
PdfIngestion repository implementation using Supabase.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from repositories.base import SupabaseRepository
from entities.pdf_ingestion import (
    PdfIngestion,
    PdfIngestionCreate,
    PdfIngestionUpdate,
    PdfIngestionFilter,
)
from common.exceptions import (
    ResourceNotFoundException,
    BusinessLogicException,
)
from common.logging import get_logger

logger = get_logger("pdf_ingestion_repository")


class PdfIngestionRepository(SupabaseRepository[PdfIngestion]):
    """Repository for PdfIngestion entity operations with Supabase."""

    def __init__(self, supabase_client, table_name: str = "pdf_ingestion"):
        super().__init__(supabase_client, table_name)

    async def create(self, ingestion_create: PdfIngestionCreate) -> PdfIngestion:
        try:
            data = ingestion_create.model_dump()
            data = self._add_audit_fields(data, is_update=False)
            # Supabase insert
            result = self.supabase.table(self.table_name).insert(data).execute()
            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to create ingestion record",
                    error_code="PDF_INGESTION_CREATE_FAILED",
                )
            created = PdfIngestion.from_dict(result.data[0])
            logger.info(f"Created ingestion record: {created.id} for {created.filename}")
            return created
        except Exception as e:
            logger.error(f"Create ingestion failed: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create ingestion record",
                error_code="PDF_INGESTION_CREATE_FAILED",
                context={"filename": ingestion_create.filename}
            )

    async def get_by_id(self, ingestion_id: str) -> Optional[PdfIngestion]:
        try:
            res = self.supabase.table(self.table_name).select("*").eq("id", ingestion_id).execute()
            if not res.data:
                return None
            return PdfIngestion.from_dict(res.data[0])
        except Exception as e:
            logger.error(f"Get ingestion by id failed: {ingestion_id}, {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve ingestion",
                error_code="PDF_INGESTION_GET_FAILED",
                context={"id": ingestion_id}
            )

    async def update(self, ingestion_id: str, update_data: PdfIngestionUpdate) -> Optional[PdfIngestion]:
        try:
            update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
            update_dict = self._add_audit_fields(update_dict, is_update=True)
            res = self.supabase.table(self.table_name).update(update_dict).eq("id", ingestion_id).execute()
            if not res.data:
                raise ResourceNotFoundException(resource_type="PdfIngestion", resource_id=ingestion_id)
            return PdfIngestion.from_dict(res.data[0])
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Update ingestion failed: {ingestion_id}, {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update ingestion",
                error_code="PDF_INGESTION_UPDATE_FAILED",
                context={"id": ingestion_id}
            )

    async def delete(self, ingestion_id: str) -> bool:
        try:
            res = self.supabase.table(self.table_name).delete().eq("id", ingestion_id).execute()
            return bool(res.data)
        except Exception as e:
            logger.error(f"Delete ingestion failed: {ingestion_id}, {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to delete ingestion",
                error_code="PDF_INGESTION_DELETE_FAILED",
                context={"id": ingestion_id}
            )

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[PdfIngestionFilter] = None,
        order_by: Optional[str] = None,
    ) -> List[PdfIngestion]:
        try:
            q = self.supabase.table(self.table_name).select("*")

            if filters:
                # Non-text filters
                simple_filters: Dict[str, Any] = {}
                if filters.compliance_domain is not None:
                    simple_filters["compliance_domain"] = filters.compliance_domain
                if filters.uploaded_by is not None:
                    simple_filters["uploaded_by"] = filters.uploaded_by
                if filters.processing_status is not None:
                    simple_filters["processing_status"] = filters.processing_status

                q = self._build_filters(q, simple_filters)

                # Version partial match
                if filters.document_version is not None:
                    q = q.ilike("document_version", f"%{filters.document_version}%")

                # Filename partial match
                if filters.filename_search is not None:
                    q = q.ilike("filename", f"%{filters.filename_search}%")

                # Date range
                if filters.ingested_after is not None:
                    q = q.gte("ingested_at", filters.ingested_after.isoformat())
                if filters.ingested_before is not None:
                    q = q.lte("ingested_at", filters.ingested_before.isoformat())

                # Tags matching
                if filters.document_tags:
                    if filters.tags_match_mode == "all":
                        q = q.contains("document_tags", filters.document_tags)
                    elif filters.tags_match_mode == "exact":
                        q = q.eq("document_tags", filters.document_tags)
                    else:
                        q = q.overlaps("document_tags", filters.document_tags)

            q = self._apply_ordering(q, order_by or "-ingested_at").range(skip, skip + limit - 1)
            res = q.execute()
            return [PdfIngestion.from_dict(r) for r in res.data]
        except Exception as e:
            logger.error(f"List ingestions failed: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to list ingestions",
                error_code="PDF_INGESTION_LIST_FAILED",
            )

    async def find_by_file_hash(self, file_hash: str) -> Optional[PdfIngestion]:
        try:
            res = self.supabase.table(self.table_name).select("*").eq("file_hash", file_hash).limit(1).execute()
            if not res.data:
                return None
            return PdfIngestion.from_dict(res.data[0])
        except Exception:
            return None

    async def soft_delete(self, ingestion_id: str) -> Optional[PdfIngestion]:
        try:
            update = {
                "processing_status": "deleted",
                "metadata": {"deleted_at": datetime.utcnow().isoformat(), "deletion_type": "soft_delete"},
            }
            update = self._add_audit_fields(update, is_update=True)
            res = self.supabase.table(self.table_name).update(update).eq("id", ingestion_id).execute()
            if not res.data:
                raise ResourceNotFoundException(resource_type="PdfIngestion", resource_id=ingestion_id)
            return PdfIngestion.from_dict(res.data[0])
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Soft delete failed: {ingestion_id}, {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to soft delete ingestion",
                error_code="PDF_INGESTION_SOFT_DELETE_FAILED",
                context={"id": ingestion_id}
            )

    async def list_by_compliance_domains(
        self,
        compliance_domains: List[str],
        skip: int = 0,
        limit: int = 10,
        order_by: Optional[str] = "-ingested_at",
    ) -> List[PdfIngestion]:
        try:
            q = (
                self.supabase
                .table(self.table_name)
                .select("*")
                .in_("compliance_domain", compliance_domains)
            )
            q = self._apply_ordering(q, order_by).range(skip, skip + limit - 1)
            res = q.execute()
            return [PdfIngestion.from_dict(r) for r in (res.data or [])]
        except Exception as e:
            logger.error(f"List by compliance domains failed: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to list ingestions by compliance domains",
                error_code="PDF_INGESTION_LIST_BY_DOMAINS_FAILED",
            )

    async def list_by_compliance_domain(
        self,
        compliance_domain: str,
        skip: int = 0,
        limit: int = 10,
        order_by: Optional[str] = "-ingested_at",
    ) -> List[PdfIngestion]:
        try:
            q = self.supabase.table(self.table_name).select("*").eq("compliance_domain", compliance_domain)
            q = self._apply_ordering(q, order_by).range(skip, skip + limit - 1)
            res = q.execute()
            return [PdfIngestion.from_dict(r) for r in (res.data or [])]
        except Exception as e:
            logger.error(f"List by compliance domain failed: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to list ingestions by compliance domain",
                error_code="PDF_INGESTION_LIST_BY_DOMAIN_FAILED",
                context={"compliance_domain": compliance_domain},
            )

    async def list_by_user(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 10,
        order_by: Optional[str] = "-ingested_at",
    ) -> List[PdfIngestion]:
        try:
            q = self.supabase.table(self.table_name).select("*").eq("uploaded_by", user_id)
            q = self._apply_ordering(q, order_by).range(skip, skip + limit - 1)
            res = q.execute()
            return [PdfIngestion.from_dict(r) for r in (res.data or [])]
        except Exception as e:
            logger.error(f"List by user failed: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to list ingestions by user",
                error_code="PDF_INGESTION_LIST_BY_USER_FAILED",
                context={"user_id": user_id},
            )

    async def list_by_version(
        self,
        document_version: str,
        skip: int = 0,
        limit: int = 10,
        exact_match: bool = False,
        order_by: Optional[str] = "-ingested_at",
    ) -> List[PdfIngestion]:
        try:
            q = self.supabase.table(self.table_name).select("*")
            if exact_match:
                q = q.eq("document_version", document_version)
            else:
                q = q.ilike("document_version", f"%{document_version}%")
            q = self._apply_ordering(q, order_by).range(skip, skip + limit - 1)
            res = q.execute()
            return [PdfIngestion.from_dict(r) for r in (res.data or [])]
        except Exception as e:
            logger.error(f"List by version failed: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to list ingestions by version",
                error_code="PDF_INGESTION_LIST_BY_VERSION_FAILED",
                context={"document_version": document_version, "exact_match": exact_match},
            )
