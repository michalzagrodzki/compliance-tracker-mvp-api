import asyncio
from typing import List, Optional, Dict, Any
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
import time

from common.exceptions import (
    ExternalServiceException,
    ValidationException
)
from common.logging import get_logger, log_performance

logger = get_logger("vector_search_adapter")


@dataclass
class VectorSearchRequest:
    """Request for vector similarity search."""
    query_embedding: List[float]
    match_threshold: float = 0.75
    match_count: int = 5
    compliance_domain: Optional[str] = None
    user_domains: Optional[List[str]] = None
    document_version: Optional[str] = None
    document_tags: Optional[List[str]] = None
    context: Optional[Dict[str, Any]] = None


@dataclass
class DocumentMatch:
    """A matched document from vector search."""
    id: str
    content: str
    similarity: float
    metadata: Dict[str, Any]


@dataclass
class VectorSearchResponse:
    """Response from vector search."""
    matches: List[DocumentMatch]
    query_metadata: Dict[str, Any]
    response_time_ms: float
    request_id: str
    total_matches: int
    created_at: datetime


class BaseVectorSearchAdapter(ABC):
    """Abstract base class for vector search adapters."""

    @abstractmethod
    async def search_similar_documents(self, request: VectorSearchRequest) -> VectorSearchResponse:
        """Search for similar documents using vector similarity."""
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """Check if the vector search service is healthy."""
        pass


class SupabaseVectorSearchAdapter(BaseVectorSearchAdapter):
    """
    Supabase vector search adapter using RPC functions.
    """

    def __init__(self, supabase_client, rpc_function: str = "match_documents_with_domain"):
        self.supabase = supabase_client
        self.rpc_function = rpc_function
        logger.info("Supabase vector search adapter initialized")

    async def search_similar_documents(self, request: VectorSearchRequest) -> VectorSearchResponse:
        """Search for similar documents using Supabase RPC function."""
        import uuid
        
        start_time = time.time()
        request_id = str(uuid.uuid4())
        
        try:
            # Validate request
            if not request.query_embedding:
                raise ValidationException(
                    detail="Query embedding cannot be empty",
                    field="query_embedding",
                    value=request.query_embedding
                )
            
            if request.match_threshold < 0 or request.match_threshold > 1:
                raise ValidationException(
                    detail="Match threshold must be between 0 and 1",
                    field="match_threshold",
                    value=request.match_threshold
                )
            
            if request.match_count < 1 or request.match_count > 100:
                raise ValidationException(
                    detail="Match count must be between 1 and 100",
                    field="match_count",
                    value=request.match_count
                )
            
            # Prepare RPC parameters
            rpc_params = {
                "query_embedding": request.query_embedding,
                "match_threshold": request.match_threshold,
                "match_count": request.match_count,
                "compliance_domain_filter": request.compliance_domain,
                "user_domains": request.user_domains,
                "document_version_filter": request.document_version,
                "document_tags_filter": request.document_tags
            }
            
            logger.debug(f"Making Supabase RPC call: {self.rpc_function}")
            
            # Execute RPC function
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.supabase.rpc(self.rpc_function, rpc_params).execute()
            )
            
            if not hasattr(response, 'data') or response.data is None:
                logger.warning("Supabase RPC returned no data")
                matches = []
            else:
                matches = response.data
            
            response_time_ms = (time.time() - start_time) * 1000
            
            # Convert to DocumentMatch objects
            document_matches = []
            for doc in matches:
                document_match = DocumentMatch(
                    id=doc.get("id", ""),
                    content=doc.get("content", ""),
                    similarity=float(doc.get("similarity", 0.0)),
                    metadata=doc.get("metadata", {})
                )
                document_matches.append(document_match)
            
            # Create response object
            search_response = VectorSearchResponse(
                matches=document_matches,
                query_metadata={
                    "match_threshold": request.match_threshold,
                    "match_count": request.match_count,
                    "compliance_domain": request.compliance_domain,
                    "document_version": request.document_version,
                    "document_tags": request.document_tags,
                    "embedding_dimensions": len(request.query_embedding)
                },
                response_time_ms=response_time_ms,
                request_id=request_id,
                total_matches=len(document_matches),
                created_at=datetime.utcnow()
            )
            
            # Log performance
            log_performance(
                operation="supabase_vector_search",
                duration_ms=response_time_ms,
                success=True,
                item_count=len(document_matches)
            )
            
            logger.info(f"Supabase vector search completed: {len(document_matches)} matches, {response_time_ms:.0f}ms")
            return search_response
            
        except ValidationException:
            raise
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="supabase_vector_search",
                duration_ms=duration_ms,
                success=False,
                error=str(e)
            )
            logger.error(f"Supabase vector search failed: {e}", exc_info=True)
            raise ExternalServiceException(
                detail="Vector search request failed",
                service_name="Supabase",
                context={"error": str(e), "rpc_function": self.rpc_function}
            )

    def is_healthy(self) -> bool:
        """Check if Supabase vector search service is healthy."""
        try:
            # Simple health check - ensure client is available
            return self.supabase is not None
        except Exception:
            return False


class MockVectorSearchAdapter(BaseVectorSearchAdapter):
    """
    Mock vector search adapter for testing and development.
    """

    def __init__(self, delay_ms: int = 100):
        self.delay_ms = delay_ms
        logger.info("Mock vector search adapter initialized")

    async def search_similar_documents(self, request: VectorSearchRequest) -> VectorSearchResponse:
        """Generate mock search results."""
        import uuid
        import random
        
        start_time = time.time()
        
        # Simulate search delay
        await asyncio.sleep(self.delay_ms / 1000)
        
        # Generate mock document matches
        mock_matches = []
        num_matches = min(request.match_count, random.randint(1, request.match_count))
        
        for i in range(num_matches):
            # Generate similarity score above threshold
            similarity = random.uniform(request.match_threshold, 1.0)
            
            mock_match = DocumentMatch(
                id=f"mock-doc-{i+1}",
                content=f"This is mock document content {i+1} that would be relevant to your query. In a real implementation, this would contain actual document text from your knowledge base.",
                similarity=similarity,
                metadata={
                    "source_filename": f"mock_document_{i+1}.pdf",
                    "compliance_domain": request.compliance_domain or "ISO27001",
                    "document_version": request.document_version or "v1.0",
                    "document_tags": request.document_tags or ["mock", "test"],
                    "chunk_index": i,
                    "author": "Mock Author",
                    "title": f"Mock Document {i+1}",
                    "mock": True
                }
            )
            mock_matches.append(mock_match)
        
        response_time_ms = (time.time() - start_time) * 1000
        
        return VectorSearchResponse(
            matches=mock_matches,
            query_metadata={
                "match_threshold": request.match_threshold,
                "match_count": request.match_count,
                "compliance_domain": request.compliance_domain,
                "document_version": request.document_version,
                "document_tags": request.document_tags,
                "embedding_dimensions": len(request.query_embedding),
                "mock": True
            },
            response_time_ms=response_time_ms,
            request_id=str(uuid.uuid4()),
            total_matches=len(mock_matches),
            created_at=datetime.utcnow()
        )

    def is_healthy(self) -> bool:
        """Mock adapter is always healthy."""
        return True