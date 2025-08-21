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
    document_versions: Optional[List[str]] = None
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
            
            # Prepare RPC parameters (omit None/empty filters to avoid over-filtering)
            base_params = {
                "query_embedding": request.query_embedding,
                "match_threshold": float(request.match_threshold),
                "match_count": int(request.match_count),
            }

            # Only include filters that are meaningfully set
            if request.compliance_domain:
                base_params["compliance_domain_filter"] = request.compliance_domain
            if request.user_domains:
                # Avoid passing empty list which some RPCs treat as no rows
                if isinstance(request.user_domains, list) and len(request.user_domains) > 0:
                    base_params["user_domains"] = request.user_domains
            # RPC expects a single text for document_version_filter, not a list
            if request.document_versions:
                # Accept both str and List[str] defensively
                dv = request.document_versions
                if isinstance(dv, list):
                    if len(dv) == 1:
                        base_params["document_version_filter"] = dv[0]
                    else:
                        # Multiple versions not supported by RPC; skip here and try relaxed/iterative fallbacks
                        logger.debug("Multiple document versions supplied; deferring version filtering to fallbacks")
                elif isinstance(dv, str):
                    base_params["document_version_filter"] = dv
            if request.document_tags:
                if isinstance(request.document_tags, list) and len(request.document_tags) > 0:
                    base_params["document_tags_filter"] = request.document_tags

            rpc_params = base_params
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

            # Fallback strategies if no matches: progressively relax constraints
            # 1) Retry without version/tags filters
            if not matches:
                relaxed_params = dict(base_params)
                relaxed_params.pop("document_version_filter", None)
                relaxed_params.pop("document_tags_filter", None)
                try:
                    fallback_resp = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: self.supabase.rpc(self.rpc_function, relaxed_params).execute()
                    )
                    if hasattr(fallback_resp, 'data') and fallback_resp.data:
                        matches = fallback_resp.data
                        logger.info("Vector search fallback: removed version/tags filters produced matches")
                except Exception as fe:
                    logger.debug(f"Vector search fallback 1 failed: {fe}")

            # 1a) If multiple versions were provided, try iterating through them until we get results
            if not matches and isinstance(request.document_versions, list) and len(request.document_versions) > 1:
                for dv in request.document_versions:
                    iter_params = dict(base_params)
                    iter_params["document_version_filter"] = dv
                    try:
                        iter_resp = await asyncio.get_event_loop().run_in_executor(
                            None,
                            lambda: self.supabase.rpc(self.rpc_function, iter_params).execute()
                        )
                        if hasattr(iter_resp, 'data') and iter_resp.data:
                            matches = (matches or []) + iter_resp.data
                            # Stop if we reached requested count
                            if len(matches) >= int(request.match_count):
                                matches = matches[: int(request.match_count)]
                                logger.info("Vector search fallback: per-version iteration produced matches")
                                break
                    except Exception as fe_iter:
                        logger.debug(f"Vector search per-version attempt failed for {dv}: {fe_iter}")

            # 2) Retry with slightly lower threshold
            if not matches:
                relaxed_low = dict(base_params)
                relaxed_low["match_threshold"] = max(0.55, float(request.match_threshold) - 0.15)
                try:
                    low_resp = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: self.supabase.rpc(self.rpc_function, relaxed_low).execute()
                    )
                    if hasattr(low_resp, 'data') and low_resp.data:
                        matches = low_resp.data
                        logger.info("Vector search fallback: lowered threshold produced matches")
                except Exception as fe2:
                    logger.debug(f"Vector search fallback 2 failed: {fe2}")
            
            response_time_ms = (time.time() - start_time) * 1000
            
            # Convert to DocumentMatch objects
            document_matches = []
            for doc in matches:
                # Some RPCs may alias fields differently; be defensive
                doc_id = doc.get("id") or doc.get("document_id") or doc.get("chunk_id") or ""
                content = doc.get("content") or doc.get("chunk_content") or doc.get("text") or ""
                sim_val = doc.get("similarity") or doc.get("score") or 0.0
                base_metadata = doc.get("metadata") or doc.get("meta") or {}
                if not isinstance(base_metadata, dict):
                    base_metadata = {"raw_metadata": base_metadata}
                merged_metadata = {
                    **base_metadata,
                    **{k: v for k, v in doc.items() if k in {
                        "compliance_domain",
                        "document_version",
                        "document_tags",
                        "source_filename",
                        "source_page_number",
                        "chunk_index"
                    }}
                }

                document_match = DocumentMatch(
                    id=str(doc_id),
                    content=str(content),
                    similarity=float(sim_val),
                    metadata=merged_metadata
                )
                document_matches.append(document_match)
            
            # Create response object
            search_response = VectorSearchResponse(
                matches=document_matches,
                query_metadata={
                    "match_threshold": request.match_threshold,
                    "match_count": request.match_count,
                    "compliance_domain": request.compliance_domain,
                    "document_version": request.document_versions,
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
