"""
Ingestion service using Repository pattern.
Coordinates PDF processing, vector store writes, and persistence.
"""

import os
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from entities.pdf_ingestion import (
    PdfIngestion,
    PdfIngestionCreate,
    PdfIngestionUpdate,
    PdfIngestionFilter,
)
from repositories.pdf_ingestion_repository import PdfIngestionRepository
from repositories.user_repository import UserRepository
from common.exceptions import (
    ValidationException,
    BusinessLogicException,
    ResourceNotFoundException,
)
from common.logging import get_logger, log_performance
from typing import Protocol

logger = get_logger("ingestion_service")


class VectorStoreAdapter(Protocol):
    def add_documents(self, documents: List[Any], **kwargs) -> List[str]:
        ...

def _calc_file_hash(file_path: str) -> str:
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


class IngestionService:
    def __init__(
        self,
        ingestion_repo: PdfIngestionRepository,
        user_repo: UserRepository,
        vector_store: VectorStoreAdapter,
    ):
        self.ingestion_repo = ingestion_repo
        self.user_repo = user_repo
        self.vector_store = vector_store

    async def create_initial_record(
        self,
        filename: str,
        compliance_domain: Optional[str],
        document_version: Optional[str],
        uploaded_by: Optional[str],
        file_size: Optional[int],
        file_hash: str,
        original_path: Optional[str],
        document_tags: Optional[List[str]] = None,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> PdfIngestion:
        data = PdfIngestionCreate(
            filename=filename,
            compliance_domain=compliance_domain,
            document_version=document_version,
            uploaded_by=uploaded_by,
            file_size=file_size,
            file_hash=file_hash,
            original_path=original_path,
            processing_status="processing",
            document_tags=document_tags or [],
            metadata={
                "processing_started_at": datetime.now(timezone.utc).isoformat(),
                **(extra_metadata or {}),
            },
        )
        return await self.ingestion_repo.create(data)

    async def ingest_pdf_sync(
        self,
        file_path: str,
        compliance_domain: Optional[str] = None,
        document_version: Optional[str] = None,
        uploaded_by: Optional[str] = None,
        document_tags: Optional[List[str]] = None,
        document_title: Optional[str] = None,
        document_author: Optional[str] = None,
    ) -> Tuple[int, str]:
        """Ingest a PDF file synchronously and persist the record via repository.

        Returns: (chunk_count, ingestion_id)
        """
        try:
            import time
            start = time.time()

            filename = os.path.basename(file_path)
            if not filename.lower().endswith(".pdf"):
                raise ValidationException(detail="Only PDF files are supported", field="filename", value=filename)

            file_size = os.path.getsize(file_path)
            file_hash = _calc_file_hash(file_path)

            # Duplicate check
            existing = await self.ingestion_repo.find_by_file_hash(file_hash)
            if existing:
                raise ValidationException(
                    detail="File already ingested",
                    field="file_hash",
                    value=file_hash,
                )

            # Create initial record
            ingestion = await self.create_initial_record(
                filename=filename,
                compliance_domain=compliance_domain,
                document_version=document_version,
                uploaded_by=uploaded_by,
                file_size=file_size,
                file_hash=file_hash,
                original_path=file_path,
                document_tags=document_tags or [],
                extra_metadata={
                    "original_filename": filename,
                    "file_size_bytes": file_size,
                    "document_tags": document_tags or [],
                    "uploaded_by": uploaded_by,
                    "title": document_title,
                    "author": document_author,
                },
            )

            # Process PDF and add to vector store
            from langchain_community.document_loaders import PyPDFLoader
            from langchain.text_splitter import RecursiveCharacterTextSplitter

            loader = PyPDFLoader(file_path)
            pages = loader.load()
            for page in pages:
                page.metadata.update(
                    {
                        "compliance_domain": compliance_domain,
                        "document_version": document_version,
                        "filename": filename,
                        "ingestion_id": ingestion.id,
                        "file_hash": file_hash,
                        "document_tags": document_tags or [],
                        "uploaded_by": uploaded_by,
                        "title": document_title,
                        "author": document_author,
                    }
                )

            splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
            chunks = splitter.split_documents(pages)

            self.vector_store.add_documents(chunks)

            # Update ingestion with completion
            update = PdfIngestionUpdate(
                processing_status="completed",
                total_chunks=len(chunks),
                metadata={
                    **(ingestion.metadata or {}),
                    "pages": len(pages),
                    "chunks": len(chunks),
                    "processing_completed_at": datetime.now(timezone.utc).isoformat(),
                    "chunk_size": 1000,
                    "chunk_overlap": 200,
                },
            )
            await self.ingestion_repo.update(ingestion.id, update)

            duration_ms = (time.time() - start) * 1000
            log_performance("pdf_ingestion", duration_ms, success=True, item_count=len(chunks))

            logger.info(f"Ingested PDF {filename}: {len(chunks)} chunks (id={ingestion.id})")
            return len(chunks), ingestion.id

        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"PDF ingestion failed: {e}", exc_info=True)
            # Try to mark record as failed if we already created one
            try:
                if 'ingestion' in locals():
                    await self.ingestion_repo.update(
                        ingestion.id,
                        PdfIngestionUpdate(
                            processing_status="failed",
                            error_message=str(e),
                            metadata={
                                **(ingestion.metadata or {}),
                                "error_occurred_at": datetime.now(timezone.utc).isoformat(),
                                "error_details": str(e),
                            },
                        ),
                    )
            except Exception:
                pass
            raise BusinessLogicException(detail="PDF processing failed", error_code="PDF_INGESTION_FAILED")

    async def get_by_id(self, ingestion_id: str) -> PdfIngestion:
        item = await self.ingestion_repo.get_by_id(ingestion_id)
        if not item:
            raise ResourceNotFoundException(resource_type="PdfIngestion", resource_id=ingestion_id)
        return item

    async def list(self, skip: int = 0, limit: int = 10, filters: Optional[PdfIngestionFilter] = None) -> List[PdfIngestion]:
        return await self.ingestion_repo.list(skip=skip, limit=limit, filters=filters)

    async def soft_delete(self, ingestion_id: str) -> PdfIngestion:
        item = await self.ingestion_repo.soft_delete(ingestion_id)
        if not item:
            raise ResourceNotFoundException(resource_type="PdfIngestion", resource_id=ingestion_id)
        return item

    # --- Convenience methods mirroring legacy services.ingestion API ---
    async def list_pdf_ingestions(self, skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
        items = await self.list(skip=skip, limit=limit, filters=PdfIngestionFilter())
        return [i.to_dict() for i in items]

    async def list_pdf_ingestions_by_compliance_domains(
        self, compliance_domains: List[str], skip: int = 0, limit: int = 10
    ) -> List[Dict[str, Any]]:
        items = await self.ingestion_repo.list_by_compliance_domains(
            compliance_domains=compliance_domains, skip=skip, limit=limit
        )
        return [i.to_dict() for i in items]

    async def get_pdf_ingestion_by_id(self, ingestion_id: str) -> Dict[str, Any]:
        item = await self.get_by_id(ingestion_id)
        return item.to_dict()

    async def get_pdf_ingestions_by_compliance_domain(
        self, compliance_domain: str, skip: int = 0, limit: int = 10
    ) -> List[Dict[str, Any]]:
        items = await self.ingestion_repo.list_by_compliance_domain(
            compliance_domain=compliance_domain, skip=skip, limit=limit
        )
        return [i.to_dict() for i in items]

    async def search_pdf_ingestions(
        self,
        compliance_domain: Optional[str] = None,
        uploaded_by: Optional[str] = None,
        document_version: Optional[str] = None,
        processing_status: Optional[str] = None,
        filename_search: Optional[str] = None,
        ingested_after: Optional[datetime] = None,
        ingested_before: Optional[datetime] = None,
        document_tags: Optional[List[str]] = None,
        tags_match_mode: str = "any",
        skip: int = 0,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        filters = PdfIngestionFilter(
            compliance_domain=compliance_domain,
            uploaded_by=uploaded_by,
            document_version=document_version,
            processing_status=processing_status,
            filename_search=filename_search,
            ingested_after=ingested_after,
            ingested_before=ingested_before,
            document_tags=document_tags,
            tags_match_mode=tags_match_mode,
        )
        items = await self.list(skip=skip, limit=limit, filters=filters)
        return [i.to_dict() for i in items]

def create_ingestion_service(
    repo: PdfIngestionRepository,
    user_repo: UserRepository,
    vector_store: VectorStoreAdapter,
) -> IngestionService:
    return IngestionService(repo, user_repo, vector_store)
