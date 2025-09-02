"""
Document service using Repository pattern.
"""
from typing import List, Optional

from entities.document import DocumentChunk, DocumentFilter
from repositories.document_repository import DocumentRepository
from common.exceptions import ValidationException
from common.logging import get_logger

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

    async def count(self, filters: Optional[DocumentFilter] = None) -> int:
        return await self.repo.count(filters)


def create_document_service(repo: DocumentRepository) -> DocumentService:
    return DocumentService(repo)
