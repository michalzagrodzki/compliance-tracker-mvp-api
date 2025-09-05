"""
RAG (Retrieval-Augmented Generation) service using Repository pattern.
Orchestrates the complete RAG pipeline: embedding, retrieval, and generation.
"""

import asyncio
import uuid
from typing import Optional, List, Dict, Any, Tuple, AsyncGenerator, Union, Iterator
from datetime import datetime

from adapters.embedding_adapter import BaseEmbeddingAdapter, EmbeddingRequest
from adapters.vector_search_adapter import BaseVectorSearchAdapter, VectorSearchRequest
from adapters.openai_adapter import BaseAIAdapter, AIRequest
from repositories.user_repository import UserRepository
from repositories.chat_history_repository import ChatHistoryRepository
from entities.chat_history import ChatHistoryCreate
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
        document_versions: Optional[List[str]] = None,
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
                document_versions=document_versions,
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
                document_versions, 
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

    def stream_answer(
        self,
        question: str,
        user_id: str,
        conversation_id: str,
        history: Optional[List[Dict[str, str]]] = None,
        match_threshold: float = 0.75,
        match_count: int = 5,
        compliance_domain: Optional[str] = None,
        document_versions: Optional[str] = None,
        document_tags: Optional[List[str]] = None,
        audit_session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Iterator[Union[str, Dict[str, Any]]]:
        """
        Stream answer using RAG pipeline.
        Yields text tokens and metadata.
        """
        import time
        start_time = time.time()
        
        # Use a dedicated event loop within this worker thread for async deps
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            # Validate user exists and has access (run async call synchronously)
            user = loop.run_until_complete(self.user_repository.get_by_id(user_id))
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
            embedding_response = loop.run_until_complete(self.embedding_adapter.generate_embedding(embedding_request))
            
            search_request = VectorSearchRequest(
                query_embedding=embedding_response.embedding,
                match_threshold=match_threshold,
                match_count=match_count,
                compliance_domain=compliance_domain,
                user_domains=user.compliance_domains if not user.is_admin() else None,
                document_versions=document_versions,
                document_tags=document_tags
            )
            
            search_response = loop.run_until_complete(self.vector_search_adapter.search_similar_documents(search_request))
            
            # Yield metadata first
            source_document_ids = [match.id for match in search_response.matches]
            metadata = self._build_query_metadata(
                search_response.matches,
                compliance_domain,
                document_versions,
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
            llm_response = loop.run_until_complete(self.llm_adapter.generate_text(llm_request))
            
            # Simulate streaming while preserving Markdown formatting
            content = llm_response.content
            chunk_size = 128
            for i in range(0, len(content), chunk_size):
                yield content[i:i+chunk_size]
            
            # Log activities (similar to non-streaming version)
            if self.chat_history_repository:
                try:
                    loop.run_until_complete(self._log_chat_history(
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
                    ))
                except Exception as e:
                    logger.warning(f"Failed to log chat history: {e}")
            
            if self.audit_log_repository and audit_session_id:
                try:
                    loop.run_until_complete(self._log_document_access(
                        user_id=user_id,
                        document_ids=source_document_ids,
                        audit_session_id=audit_session_id,
                        compliance_domain=compliance_domain,
                        question=question,
                        answer=llm_response.content,
                        ip_address=ip_address,
                        user_agent=user_agent
                    ))
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
        finally:
            try:
                loop.close()
            except Exception:
                pass

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
        document_versions: Optional[List[str]],
        document_tags: Optional[List[str]],
        embedding_response,
        llm_response
    ) -> Dict[str, Any]:
        """Build aggregated metadata matching the required structure."""
        # Collect metadata from source documents
        source_filenames: set[str] = set()
        source_domains: set[str] = set()
        source_versions: set[str] = set()
        all_tags: set[str] = set()

        total_similarity_score = 0.0
        best_match_score = 0.0
        min_similarity = None
        max_similarity = None
        document_details: List[Dict[str, Any]] = []

        for match in matches:
            md = match.metadata or {}

            if md.get("source_filename"):
                source_filenames.add(md["source_filename"])
            if md.get("compliance_domain"):
                source_domains.add(md["compliance_domain"])
            if md.get("document_version"):
                source_versions.add(md["document_version"])
            if md.get("document_tags"):
                try:
                    all_tags.update(list(md["document_tags"]))
                except Exception:
                    pass

            sim = float(getattr(match, "similarity", 0.0) or 0.0)
            total_similarity_score += sim
            best_match_score = sim if sim > best_match_score else best_match_score
            min_similarity = sim if (min_similarity is None or sim < min_similarity) else min_similarity
            max_similarity = sim if (max_similarity is None or sim > max_similarity) else max_similarity

            document_details.append({
                "title": md.get("title"),
                "author": md.get("author"),
                "similarity": sim,
                "chunk_index": md.get("chunk_index"),
                "document_id": str(match.id),
                "document_tags": md.get("document_tags", []) or [],
                "source_filename": md.get("source_filename"),
                "document_version": md.get("document_versions"),
                "compliance_domain": md.get("compliance_domain"),
                "source_page_number": md.get("source_page_number"),
            })

        count = len(matches)
        avg_similarity = (total_similarity_score / count) if count else 0.0

        # Derive summaries
        tags_lower = {t.lower() for t in all_tags}
        regulatory_tags = [t for t in all_tags if any(k in t.lower() for k in ["iso", "gdpr", "sox", "hipaa", "pci"])]
        document_types = [t for t in all_tags if any(k in t.lower() for k in ["policy", "procedure", "standard", "guideline"])]

        # Build aggregated metadata with only allowed keys
        base_metadata: Dict[str, Any] = {
            "queried_tags": document_tags if document_tags else None,
            "queried_domain": compliance_domain,
            "source_domains": list(source_domains),
            "queried_version": document_versions,
            "source_versions": list(source_versions),
            "best_match_score": best_match_score,
            "document_details": document_details,
            "similarity_range": {
                "min": (min_similarity if min_similarity is not None else 0.0),
                "max": (max_similarity if max_similarity is not None else 0.0),
            },
            "source_filenames": list(source_filenames),
            "all_document_tags": list(all_tags),
            "average_similarity": round(avg_similarity, 4),
            "compliance_summary": {
                "document_types": document_types,
                "domains_covered": list(source_domains),
                "regulatory_tags": regulatory_tags,
                "versions_referenced": list(source_versions),
            },
            "total_documents_retrieved": count,
        }

        return base_metadata

    async def _log_chat_history(self, **kwargs):
        """Persist chat history using repository."""
        if not self.chat_history_repository:
            return
        try:
            # Build create model; tolerate extra fields in kwargs
            create = ChatHistoryCreate(**{
                "conversation_id": kwargs.get("conversation_id"),
                "question": kwargs.get("question"),
                "answer": kwargs.get("answer"),
                "audit_session_id": kwargs.get("audit_session_id"),
                "compliance_domain": kwargs.get("compliance_domain"),
                "source_document_ids": kwargs.get("source_document_ids", []) or [],
                "match_threshold": kwargs.get("match_threshold"),
                "match_count": kwargs.get("match_count"),
                "user_id": kwargs.get("user_id"),
                "response_time_ms": kwargs.get("response_time_ms"),
                "total_tokens_used": kwargs.get("total_tokens_used"),
                "metadata": kwargs.get("metadata", {}) or {},
            })
            item = await self.chat_history_repository.create(create)
            logger.info(f"Chat history saved: conversation={item.conversation_id} id={item.id}")
        except Exception as e:
            logger.warning(f"Failed to persist chat history: {e}")

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
