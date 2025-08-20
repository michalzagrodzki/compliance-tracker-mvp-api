"""
RAG (Retrieval-Augmented Generation) service using Repository pattern.
Orchestrates the complete RAG pipeline: embedding, retrieval, and generation.
"""

import asyncio
import uuid
from typing import Optional, List, Dict, Any, Tuple, AsyncGenerator, Union
from datetime import datetime

from adapters.embedding_adapter import BaseEmbeddingAdapter, EmbeddingRequest
from adapters.vector_search_adapter import BaseVectorSearchAdapter, VectorSearchRequest
from adapters.openai_adapter import BaseAIAdapter, AIRequest
from repositories.user_repository import UserRepository
from repositories.chat_history_repository import ChatHistoryRepository
from repositories.audit_log_repository import AuditLogRepository
from entities.audit_log import AuditLogCreate
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException,
    AuthorizationException
)
from common.logging import get_logger, log_business_event, log_performance

logger = get_logger("rag_service")


class RAGService:
    """
    RAG service using adapter pattern.
    Handles business logic for retrieval-augmented generation.
    """

    def __init__(
        self, 
        embedding_adapter: BaseEmbeddingAdapter,
        vector_search_adapter: BaseVectorSearchAdapter,
        llm_adapter: BaseAIAdapter,
        user_repository: UserRepository,
        chat_history_repository: Optional[ChatHistoryRepository] = None,
        audit_log_repository: Optional[AuditLogRepository] = None
    ):
        self.embedding_adapter = embedding_adapter
        self.vector_search_adapter = vector_search_adapter
        self.llm_adapter = llm_adapter
        self.user_repository = user_repository
        self.chat_history_repository = chat_history_repository
        self.audit_log_repository = audit_log_repository

    async def answer_question(
        self,
        question: str,
        user_id: str,
        match_threshold: float = 0.75,
        match_count: int = 5,
        compliance_domain: Optional[str] = None,
        document_version: Optional[str] = None,
        document_tags: Optional[List[str]] = None,
        conversation_id: Optional[str] = None,
        audit_session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Tuple[str, List[Dict[str, Any]], Dict[str, Any]]:
        """
        Answer a question using RAG pipeline.
        Returns (answer, source_documents, metadata).
        """
        import time
        start_time = time.time()
        
        try:
            # Validate user exists and has access
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive user",
                    field="user_id",
                    value=user_id
                )
            
            # Check domain access if specified
            if compliance_domain and not (user.is_admin() or user.can_access_domain(compliance_domain)):
                raise AuthorizationException(
                    detail=f"Access denied to compliance domain: {compliance_domain}",
                    error_code="DOMAIN_ACCESS_DENIED"
                )
            
            # Step 1: Generate embedding for the question
            embedding_request = EmbeddingRequest(text=question)
            embedding_response = await self.embedding_adapter.generate_embedding(embedding_request)
            
            # Step 2: Search for similar documents
            search_request = VectorSearchRequest(
                query_embedding=embedding_response.embedding,
                match_threshold=match_threshold,
                match_count=match_count,
                compliance_domain=compliance_domain,
                user_domains=user.compliance_domains if not user.is_admin() else None,
                document_version=document_version,
                document_tags=document_tags
            )
            
            search_response = await self.vector_search_adapter.search_similar_documents(search_request)
            
            # Step 3: Generate answer using LLM
            context_docs = [
                f"Source {i+1}: {match.content}" 
                for i, match in enumerate(search_response.matches)
            ]
            
            rag_prompt = self._build_rag_prompt(question, context_docs, compliance_domain)
            
            llm_request = AIRequest(
                prompt=rag_prompt,
                context={
                    "role": "compliance expert",
                    "domain": compliance_domain or "general compliance",
                    "instructions": "Provide accurate, helpful responses based on the provided context. Cite sources when possible."
                }
            )
            
            llm_response = await self.llm_adapter.generate_text(llm_request)
            
            # Step 4: Prepare response data
            source_documents = [
                {
                    "id": match.id,
                    "content": match.content,
                    "similarity": match.similarity,
                    "metadata": match.metadata
                }
                for match in search_response.matches
            ]
            
            # Build aggregated metadata
            metadata = self._build_query_metadata(
                search_response.matches, 
                compliance_domain, 
                document_version, 
                document_tags,
                embedding_response,
                llm_response
            )
            
            # Step 5: Log chat history if repository is available
            if self.chat_history_repository and conversation_id:
                try:
                    await self._log_chat_history(
                        conversation_id=conversation_id,
                        question=question,
                        answer=llm_response.content,
                        audit_session_id=audit_session_id,
                        compliance_domain=compliance_domain,
                        source_document_ids=[match.id for match in search_response.matches],
                        user_id=user_id,
                        match_threshold=match_threshold,
                        match_count=match_count,
                        response_time_ms=int((time.time() - start_time) * 1000),
                        total_tokens_used=llm_response.tokens_used,
                        metadata=metadata
                    )
                except Exception as e:
                    logger.warning(f"Failed to log chat history: {e}")
            
            # Step 6: Log audit entries if repository is available
            if self.audit_log_repository and audit_session_id:
                try:
                    await self._log_document_access(
                        user_id=user_id,
                        document_ids=[match.id for match in search_response.matches],
                        audit_session_id=audit_session_id,
                        compliance_domain=compliance_domain,
                        question=question,
                        answer=llm_response.content,
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                except Exception as e:
                    logger.warning(f"Failed to log audit entries: {e}")
            
            # Log business event
            log_business_event(
                event_type="RAG_QUESTION_ANSWERED",
                entity_type="rag_query",
                entity_id=conversation_id or str(uuid.uuid4()),
                action="query",
                user_id=user_id,
                details={
                    "question_length": len(question),
                    "documents_retrieved": len(search_response.matches),
                    "compliance_domain": compliance_domain,
                    "tokens_used": llm_response.tokens_used
                }
            )
            
            # Log performance
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="rag_answer_question",
                duration_ms=duration_ms,
                success=True,
                token_count=llm_response.tokens_used,
                item_count=len(search_response.matches)
            )
            
            return llm_response.content, source_documents, metadata
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="rag_answer_question",
                duration_ms=duration_ms,
                success=False,
                error=str(e)
            )
            logger.error(f"Failed to answer question: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to process question",
                error_code="RAG_PROCESSING_FAILED",
                context={"question_length": len(question)}
            )

    async def stream_answer(
        self,
        question: str,
        user_id: str,
        conversation_id: str,
        history: Optional[List[Dict[str, str]]] = None,
        match_threshold: float = 0.75,
        match_count: int = 5,
        compliance_domain: Optional[str] = None,
        document_version: Optional[str] = None,
        document_tags: Optional[List[str]] = None,
        audit_session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AsyncGenerator[Union[str, Dict[str, Any]], None]:
        """
        Stream answer using RAG pipeline.
        Yields text tokens and metadata.
        """
        import time
        start_time = time.time()
        
        try:
            # Validate user exists and has access
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive user",
                    field="user_id",
                    value=user_id
                )
            
            # Check domain access if specified
            if compliance_domain and not (user.is_admin() or user.can_access_domain(compliance_domain)):
                raise AuthorizationException(
                    detail=f"Access denied to compliance domain: {compliance_domain}",
                    error_code="DOMAIN_ACCESS_DENIED"
                )
            
            # Step 1: Generate embedding and search for documents
            embedding_request = EmbeddingRequest(text=question)
            embedding_response = await self.embedding_adapter.generate_embedding(embedding_request)
            
            search_request = VectorSearchRequest(
                query_embedding=embedding_response.embedding,
                match_threshold=match_threshold,
                match_count=match_count,
                compliance_domain=compliance_domain,
                user_domains=user.compliance_domains if not user.is_admin() else None,
                document_version=document_version,
                document_tags=document_tags
            )
            
            search_response = await self.vector_search_adapter.search_similar_documents(search_request)
            
            # Yield metadata first
            source_document_ids = [match.id for match in search_response.matches]
            metadata = self._build_query_metadata(
                search_response.matches,
                compliance_domain,
                document_version,
                document_tags,
                embedding_response,
                None  # LLM response not available yet
            )
            
            yield {"source_document_ids": source_document_ids}
            yield {"metadata": metadata}
            
            # Step 2: Stream LLM response
            # Note: This is a simplified version. For real streaming, you'd need
            # to implement streaming support in the OpenAI adapter
            context_docs = [
                f"Source {i+1}: {match.content}" 
                for i, match in enumerate(search_response.matches)
            ]
            
            rag_prompt = self._build_rag_prompt(question, context_docs, compliance_domain, history)
            
            llm_request = AIRequest(
                prompt=rag_prompt,
                context={
                    "role": "compliance expert",
                    "domain": compliance_domain or "general compliance",
                    "instructions": (
                        "Provide accurate, helpful responses based on the provided context. "
                        "Format the answer in clear Markdown (use headings, bullet lists, and code blocks when helpful)."
                    )
                }
            )
            
            # For now, generate the full response and yield it token by token
            # In a real implementation, you'd want streaming support in the LLM adapter
            llm_response = await self.llm_adapter.generate_text(llm_request)
            
            # Simulate streaming while preserving Markdown formatting
            content = llm_response.content
            chunk_size = 128
            for i in range(0, len(content), chunk_size):
                yield content[i:i+chunk_size]
                await asyncio.sleep(0.01)
            
            # Log activities (similar to non-streaming version)
            if self.chat_history_repository:
                try:
                    await self._log_chat_history(
                        conversation_id=conversation_id,
                        question=question,
                        answer=llm_response.content,
                        audit_session_id=audit_session_id,
                        compliance_domain=compliance_domain,
                        source_document_ids=source_document_ids,
                        user_id=user_id,
                        match_threshold=match_threshold,
                        match_count=match_count,
                        response_time_ms=int((time.time() - start_time) * 1000),
                        total_tokens_used=llm_response.tokens_used,
                        metadata=metadata
                    )
                except Exception as e:
                    logger.warning(f"Failed to log chat history: {e}")
            
            if self.audit_log_repository and audit_session_id:
                try:
                    await self._log_document_access(
                        user_id=user_id,
                        document_ids=source_document_ids,
                        audit_session_id=audit_session_id,
                        compliance_domain=compliance_domain,
                        question=question,
                        answer=llm_response.content,
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                except Exception as e:
                    logger.warning(f"Failed to log audit entries: {e}")
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to stream answer: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to stream response",
                error_code="RAG_STREAMING_FAILED",
                context={"question_length": len(question)}
            )

    def _build_rag_prompt(
        self, 
        question: str, 
        context_docs: List[str], 
        compliance_domain: Optional[str] = None,
        history: Optional[List[Dict[str, str]]] = None
    ) -> str:
        """Build the RAG prompt with context documents."""
        
        prompt_parts = []
        
        # Add system context
        if compliance_domain:
            prompt_parts.append(f"You are a compliance expert specializing in {compliance_domain}.")
        else:
            prompt_parts.append("You are a compliance expert.")
        
        # Add conversation history if available
        if history:
            prompt_parts.append("Previous conversation:")
            for entry in history[-5:]:  # Last 5 entries
                if entry.get("question"):
                    prompt_parts.append(f"Q: {entry['question']}")
                if entry.get("answer"):
                    prompt_parts.append(f"A: {entry['answer']}")
            prompt_parts.append("")
        
        # Add context documents
        if context_docs:
            prompt_parts.append("Based on the following relevant documents:")
            prompt_parts.append("")
            for doc in context_docs:
                prompt_parts.append(doc)
                prompt_parts.append("")
        
        # Add the actual question
        prompt_parts.append(f"Question: {question}")
        prompt_parts.append("")
        prompt_parts.append("Please provide a comprehensive answer based on the provided context. If the context doesn't contain enough information to fully answer the question, please indicate what additional information would be needed.")
        
        return "\n".join(prompt_parts)

    def _build_query_metadata(
        self,
        matches: List,
        compliance_domain: Optional[str],
        document_version: Optional[str],
        document_tags: Optional[List[str]],
        embedding_response,
        llm_response
    ) -> Dict[str, Any]:
        """Build aggregated metadata from the RAG pipeline."""
        
        # Collect metadata from source documents
        source_filenames = set()
        source_domains = set()
        source_versions = set()
        all_tags = set()
        authors = set()
        titles = set()
        
        total_similarity_score = 0.0
        best_match_score = 0.0
        document_details = []
        
        for match in matches:
            metadata = match.metadata or {}
            
            if metadata.get("source_filename"):
                source_filenames.add(metadata["source_filename"])
            if metadata.get("compliance_domain"):
                source_domains.add(metadata["compliance_domain"])
            if metadata.get("document_version"):
                source_versions.add(metadata["document_version"])
            if metadata.get("document_tags"):
                all_tags.update(metadata["document_tags"])
            if metadata.get("author"):
                authors.add(metadata["author"])
            if metadata.get("title"):
                titles.add(metadata["title"])
            
            similarity = match.similarity
            total_similarity_score += similarity
            best_match_score = max(best_match_score, similarity)
            
            document_details.append({
                "id": match.id,
                "source_filename": metadata.get("source_filename"),
                "compliance_domain": metadata.get("compliance_domain"),
                "document_version": metadata.get("document_version"),
                "similarity": similarity,
                "chunk_index": metadata.get("chunk_index", 0)
            })
        
        avg_similarity = total_similarity_score / len(matches) if matches else 0.0
        
        return {
            "query_metadata": {
                "requested_compliance_domain": compliance_domain,
                "requested_document_version": document_version,
                "requested_document_tags": document_tags or [],
                "sources_analyzed": len(matches),
                "embedding_model": getattr(embedding_response, 'model_used', None),
                "llm_model": getattr(llm_response, 'model_used', None) if llm_response else None
            },
            "document_coverage": {
                "unique_source_files": list(source_filenames),
                "unique_compliance_domains": list(source_domains),
                "unique_document_versions": list(source_versions),
                "all_document_tags": list(all_tags),
                "unique_authors": list(authors),
                "unique_titles": list(titles),
                "total_sources": len(matches)
            },
            "similarity_metrics": {
                "best_match_score": round(best_match_score, 4),
                "average_similarity": round(avg_similarity, 4),
                "total_similarity": round(total_similarity_score, 4)
            },
            "document_details": document_details,
            "performance_metrics": {
                "embedding_tokens": getattr(embedding_response, 'token_count', None),
                "embedding_time_ms": getattr(embedding_response, 'response_time_ms', None),
                "llm_tokens": getattr(llm_response, 'tokens_used', None) if llm_response else None,
                "llm_time_ms": getattr(llm_response, 'response_time_ms', None) if llm_response else None
            }
        }

    async def _log_chat_history(self, **kwargs):
        """Log chat history entry."""
        # Implementation depends on chat history repository structure
        # This is a placeholder that would need to be implemented based on your specific requirements
        logger.debug(f"Logging chat history: {kwargs}")

    async def _log_document_access(
        self,
        user_id: str,
        document_ids: List[str],
        audit_session_id: str,
        compliance_domain: Optional[str],
        question: str,
        answer: str,
        ip_address: Optional[str],
        user_agent: Optional[str]
    ):
        """Log document access for audit trail."""
        for doc_id in document_ids:
            audit_log_create = AuditLogCreate(
                object_type="document",
                object_id=doc_id,
                action="reference",
                user_id=user_id,
                audit_session_id=audit_session_id,
                compliance_domain=compliance_domain,
                ip_address=ip_address,
                user_agent=user_agent,
                risk_level="medium",
                details={"query_text": question, "answer": answer}
            )
            
            await self.audit_log_repository.create(audit_log_create)


# Factory function
def create_rag_service(
    embedding_adapter: BaseEmbeddingAdapter,
    vector_search_adapter: BaseVectorSearchAdapter,
    llm_adapter: BaseAIAdapter,
    user_repository: UserRepository,
    chat_history_repository: Optional[ChatHistoryRepository] = None,
    audit_log_repository: Optional[AuditLogRepository] = None
) -> RAGService:
    """Factory function to create RAGService instance."""
    return RAGService(
        embedding_adapter,
        vector_search_adapter,
        llm_adapter,
        user_repository,
        chat_history_repository,
        audit_log_repository
    )
