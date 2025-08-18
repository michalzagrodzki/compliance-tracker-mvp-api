"""
Document service using Repository pattern.
"""

from typing import List, Dict, Any, Optional

from entities.document import DocumentChunk, DocumentFilter
from repositories.document_repository import DocumentRepository
from common.exceptions import ValidationException
from common.logging import get_logger, log_performance

logger = get_logger("document_service")


class DocumentService:
    def __init__(self, repo: DocumentRepository):
        self.repo = repo

    async def list(
        self,
        skip: int = 0,
        limit: int = 10,
        filters: Optional[DocumentFilter] = None,
        order_by: Optional[str] = None,
    ) -> List[DocumentChunk]:
        return await self.repo.list(skip=skip, limit=limit, filters=filters, order_by=order_by)

    async def get_by_id(self, doc_id: str) -> Optional[DocumentChunk]:
        return await self.repo.get_by_id(doc_id)

    async def by_source(self, source_filename: str) -> List[DocumentChunk]:
        if not source_filename:
            raise ValidationException(detail="source_filename required", field="source_filename")
        return await self.repo.list_by_source_filename(source_filename)

    async def by_domain(self, domain: str, skip: int = 0, limit: int = 50) -> List[DocumentChunk]:
        return await self.repo.list_by_domain(domain, skip=skip, limit=limit)

    async def by_version(self, version: str, skip: int = 0, limit: int = 50) -> List[DocumentChunk]:
        return await self.repo.list_by_version(version, skip=skip, limit=limit)

    async def by_domain_and_version(
        self, domain: str, version: str, skip: int = 0, limit: int = 50
    ) -> List[DocumentChunk]:
        return await self.repo.list_by_domain_and_version(domain, version, skip=skip, limit=limit)

    async def by_tags(
        self, tags: List[str], match_mode: str = "any", compliance_domain: Optional[str] = None, skip: int = 0, limit: int = 50
    ) -> List[DocumentChunk]:
        if not tags:
            raise ValidationException(detail="tags cannot be empty", field="document_tags")
        if match_mode not in ["any", "all", "exact"]:
            raise ValidationException(detail="invalid match_mode", field="tags_match_mode", value=match_mode)
        return await self.repo.list_by_tags(tags, match_mode, compliance_domain, skip=skip, limit=limit)

    async def count(self, filters: Optional[DocumentFilter] = None) -> int:
        return await self.repo.count(filters)


def create_document_service(repo: DocumentRepository) -> DocumentService:
    return DocumentService(repo)
