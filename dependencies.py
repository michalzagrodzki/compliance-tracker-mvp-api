"""
Dependency injection setup for repositories and services.
"""

from functools import lru_cache
from typing import Annotated
from fastapi import Depends

from db.supabase_client import create_supabase_client
from repositories.user_repository import UserRepository
from repositories.pdf_ingestion_repository import PdfIngestionRepository
from repositories.chat_history_repository import ChatHistoryRepository
from repositories.compliance_gap_repository import ComplianceGapRepository
from repositories.document_repository import DocumentRepository
from repositories.iso_control_repository import ISOControlRepository
from repositories.audit_log_repository import AuditLogRepository
from services.auth_service import AuthService, create_auth_service
from services.compliance_gap_service import ComplianceGapService, create_compliance_gap_service
from services.document_service import DocumentService, create_document_service
from services.ingestion_service import IngestionService, create_ingestion_service
from services.chat_history_service import ChatHistoryService, create_chat_history_service
from services.ai_service import AIService, create_ai_service
from services.compliance_recommendation_service import ComplianceRecommendationService, create_compliance_recommendation_service
from services.iso_control_service import ISOControlService, create_iso_control_service
from services.audit_log_service import AuditLogService, create_audit_log_service
from adapters.openai_adapter import OpenAIAdapter, MockAIAdapter
from adapters.embedding_adapter import BaseEmbeddingAdapter, OpenAIEmbeddingAdapter, MockEmbeddingAdapter
from adapters.vector_search_adapter import BaseVectorSearchAdapter, SupabaseVectorSearchAdapter, MockVectorSearchAdapter
from services.rag_service import RAGService, create_rag_service
from config.config import settings


@lru_cache()
def get_supabase_client():
    """Get singleton Supabase client."""
    return create_supabase_client()


@lru_cache()
def get_user_repository() -> UserRepository:
    """Get singleton User repository."""
    supabase = get_supabase_client()
    return UserRepository(supabase, settings.supabase_table_users)


@lru_cache()
def get_compliance_gap_repository() -> ComplianceGapRepository:
    """Get singleton ComplianceGap repository."""
    supabase = get_supabase_client()
    return ComplianceGapRepository(supabase, settings.supabase_table_compliance_gaps)


@lru_cache()
def get_document_repository() -> DocumentRepository:
    """Get singleton Document repository."""
    supabase = get_supabase_client()
    return DocumentRepository(supabase, settings.supabase_table_documents)


@lru_cache()
def get_iso_control_repository() -> ISOControlRepository:
    """Get singleton ISO Control repository."""
    supabase = get_supabase_client()
    return ISOControlRepository(supabase, settings.supabase_table_iso_controls)


@lru_cache()
def get_audit_log_repository() -> AuditLogRepository:
    """Get singleton Audit Log repository."""
    supabase = get_supabase_client()
    return AuditLogRepository(supabase, settings.supabase_table_audit_log)


@lru_cache()
def get_auth_service() -> AuthService:
    """Get singleton AuthService with dependencies."""
    supabase = get_supabase_client()
    user_repo = get_user_repository()
    return create_auth_service(supabase, user_repo)


@lru_cache()
def get_compliance_gap_service() -> ComplianceGapService:
    """Get singleton ComplianceGapService with dependencies."""
    gap_repo = get_compliance_gap_repository()
    user_repo = get_user_repository()
    return create_compliance_gap_service(gap_repo, user_repo)


@lru_cache()
def get_document_service() -> DocumentService:
    repo = get_document_repository()
    return create_document_service(repo)


@lru_cache()
def get_iso_control_service() -> ISOControlService:
    """Get singleton ISOControlService with dependencies."""
    iso_control_repo = get_iso_control_repository()
    user_repo = get_user_repository()
    return create_iso_control_service(iso_control_repo, user_repo)


@lru_cache()
def get_audit_log_service() -> AuditLogService:
    """Get singleton AuditLogService with dependencies."""
    audit_log_repo = get_audit_log_repository()
    user_repo = get_user_repository()
    return create_audit_log_service(audit_log_repo, user_repo)


@lru_cache()
def get_pdf_ingestion_repository() -> PdfIngestionRepository:
    """Get singleton PdfIngestion repository."""
    supabase = get_supabase_client()
    return PdfIngestionRepository(supabase, settings.supabase_table_pdf_ingestion)


@lru_cache()
def get_ingestion_service() -> IngestionService:
    """Get singleton IngestionService with dependencies."""
    repo = get_pdf_ingestion_repository()
    user_repo = get_user_repository()
    return create_ingestion_service(repo, user_repo)


@lru_cache()
def get_chat_history_repository() -> ChatHistoryRepository:
    """Get singleton ChatHistory repository."""
    supabase = get_supabase_client()
    return ChatHistoryRepository(supabase, settings.supabase_table_chat_history)


@lru_cache()
def get_chat_history_service() -> ChatHistoryService:
    repo = get_chat_history_repository()
    return create_chat_history_service(repo)


@lru_cache()
def get_ai_adapter():
    """Get AI adapter (OpenAI or Mock based on configuration)."""
    # Check if we have OpenAI API key
    openai_api_key = getattr(settings, 'openai_api_key', None)
    
    if openai_api_key:
        return OpenAIAdapter(api_key=openai_api_key)
    else:
        # Fall back to mock adapter for development/testing
        return MockAIAdapter(delay_ms=500)


@lru_cache()
def get_ai_service() -> AIService:
    """Get singleton AIService with dependencies."""
    ai_adapter = get_ai_adapter()
    return create_ai_service(ai_adapter, enable_cache=True)


@lru_cache()
def get_compliance_recommendation_service() -> ComplianceRecommendationService:
    """Get singleton ComplianceRecommendationService with dependencies."""
    ai_service = get_ai_service()
    gap_repo = get_compliance_gap_repository()
    user_repo = get_user_repository()
    return create_compliance_recommendation_service(ai_service, gap_repo, user_repo)


@lru_cache()
def get_embedding_adapter() -> BaseEmbeddingAdapter:
    """Get embedding adapter (OpenAI or Mock based on configuration)."""
    openai_api_key = getattr(settings, 'openai_api_key', None)
    
    if openai_api_key:
        return OpenAIEmbeddingAdapter(api_key=openai_api_key)
    else:
        return MockEmbeddingAdapter(delay_ms=100)


@lru_cache()
def get_vector_search_adapter() -> BaseVectorSearchAdapter:
    """Get vector search adapter (Supabase or Mock based on configuration)."""
    try:
        supabase = get_supabase_client()
        return SupabaseVectorSearchAdapter(supabase)
    except Exception:
        return MockVectorSearchAdapter(delay_ms=200)


@lru_cache()
def get_rag_service() -> RAGService:
    """Get singleton RAGService with dependencies."""
    embedding_adapter = get_embedding_adapter()
    vector_search_adapter = get_vector_search_adapter()
    llm_adapter = get_ai_adapter()
    user_repo = get_user_repository()
    chat_history_repo = get_chat_history_repository()
    audit_log_repo = get_audit_log_repository()
    
    return create_rag_service(
        embedding_adapter,
        vector_search_adapter,
        llm_adapter,
        user_repo,
        chat_history_repo,
        audit_log_repo
    )


# Dependency annotations for FastAPI
SupabaseClient = Annotated[object, Depends(get_supabase_client)]
UserRepositoryDep = Annotated[UserRepository, Depends(get_user_repository)]
ComplianceGapRepositoryDep = Annotated[ComplianceGapRepository, Depends(get_compliance_gap_repository)]
AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]
ComplianceGapServiceDep = Annotated[ComplianceGapService, Depends(get_compliance_gap_service)]
DocumentRepositoryDep = Annotated[DocumentRepository, Depends(get_document_repository)]
DocumentServiceDep = Annotated[DocumentService, Depends(get_document_service)]
ISOControlRepositoryDep = Annotated[ISOControlRepository, Depends(get_iso_control_repository)]
ISOControlServiceDep = Annotated[ISOControlService, Depends(get_iso_control_service)]
AuditLogRepositoryDep = Annotated[AuditLogRepository, Depends(get_audit_log_repository)]
AuditLogServiceDep = Annotated[AuditLogService, Depends(get_audit_log_service)]
IngestionRepositoryDep = Annotated[PdfIngestionRepository, Depends(get_pdf_ingestion_repository)]
IngestionServiceDep = Annotated[IngestionService, Depends(get_ingestion_service)]
ChatHistoryRepositoryDep = Annotated[ChatHistoryRepository, Depends(get_chat_history_repository)]
ChatHistoryServiceDep = Annotated[ChatHistoryService, Depends(get_chat_history_service)]
AIServiceDep = Annotated[AIService, Depends(get_ai_service)]
ComplianceRecommendationServiceDep = Annotated[ComplianceRecommendationService, Depends(get_compliance_recommendation_service)]
EmbeddingAdapterDep = Annotated[BaseEmbeddingAdapter, Depends(get_embedding_adapter)]
VectorSearchAdapterDep = Annotated[BaseVectorSearchAdapter, Depends(get_vector_search_adapter)]
RAGServiceDep = Annotated[RAGService, Depends(get_rag_service)]
