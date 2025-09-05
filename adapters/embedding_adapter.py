"""
Embedding adapter for vector embedding generation.
This handles all embedding-related operations for RAG functionality.
"""

import asyncio
from typing import List, Optional, Dict, Any
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
import time
from openai import AsyncOpenAI
from common.exceptions import (
    ExternalServiceException,
    ValidationException,
    BusinessLogicException
)
from common.logging import get_logger, log_performance
from config.config import settings

logger = get_logger("embedding_adapter")


@dataclass
class EmbeddingRequest:
    """Request for embedding generation."""
    text: str
    model: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


@dataclass
class EmbeddingResponse:
    """Response from embedding generation."""
    embedding: List[float]
    model_used: str
    token_count: int
    response_time_ms: float
    request_id: str
    metadata: Dict[str, Any]
    created_at: datetime


class BaseEmbeddingAdapter(ABC):
    """Abstract base class for embedding service adapters."""

    @abstractmethod
    async def generate_embedding(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Generate embedding for text."""
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """Check if the embedding service is healthy."""
        pass


class OpenAIEmbeddingAdapter(BaseEmbeddingAdapter):
    """
    OpenAI embedding adapter for text embedding generation.
    """
    def __init__(self, api_key: str, default_model: str = settings.embedding_model, timeout: int = 30):
        self.api_key = api_key
        self.default_model = default_model
        self.timeout = timeout
        self._client = None
        self._initialize_client()

    def _initialize_client(self):
        try:
            self._client = AsyncOpenAI(api_key=self.api_key)
            logger.info("OpenAI embedding client initialized successfully")
        except ImportError:
            logger.error("OpenAI library not installed. Install with: pip install openai")
            raise BusinessLogicException(
                detail="OpenAI library not available",
                error_code="DEPENDENCY_MISSING"
            )
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI embedding client: {e}")
            raise ExternalServiceException(
                detail="Failed to initialize OpenAI embedding client",
                service_name="OpenAI",
                context={"error": str(e)}
            )

    async def generate_embedding(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Generate embedding using OpenAI API."""
        import uuid
        
        start_time = time.time()
        request_id = str(uuid.uuid4())
        
        try:
            # Validate request
            if not request.text or not request.text.strip():
                raise ValidationException(
                    detail="Text cannot be empty",
                    field="text",
                    value=request.text
                )
            
            # Prepare API call
            model = request.model or self.default_model
            
            logger.debug(f"Making OpenAI embedding API call with model: {model}")
            
            # Call OpenAI API
            response = await asyncio.wait_for(
                self._client.embeddings.create(
                    model=model,
                    input=request.text.strip()
                ),
                timeout=self.timeout
            )
            
            # Extract response data
            embedding = response.data[0].embedding
            # Some SDK versions/models may omit usage for embeddings; handle defensively
            token_count = getattr(getattr(response, "usage", None), "total_tokens", 0) or 0
            response_time_ms = (time.time() - start_time) * 1000
            
            # Create response object
            embedding_response = EmbeddingResponse(
                embedding=embedding,
                model_used=response.model,
                token_count=token_count,
                response_time_ms=response_time_ms,
                request_id=request_id,
                metadata={
                    "prompt_tokens": getattr(getattr(response, "usage", None), "prompt_tokens", 0) or 0,
                    "total_tokens": token_count,
                    "text_length": len(request.text),
                    "embedding_dimensions": len(embedding)
                },
                created_at=datetime.utcnow()
            )
            
            # Log performance
            log_performance(
                operation="openai_embedding_generation",
                duration_ms=response_time_ms,
                success=True,
                token_count=token_count
            )
            
            logger.info(f"OpenAI embedding generation completed: {token_count} tokens, {response_time_ms:.0f}ms")
            return embedding_response
            
        except asyncio.TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="openai_embedding_generation",
                duration_ms=duration_ms,
                success=False,
                error="timeout"
            )
            raise ExternalServiceException(
                detail="OpenAI embedding API request timed out",
                service_name="OpenAI",
                context={"timeout_seconds": self.timeout}
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="openai_embedding_generation",
                duration_ms=duration_ms,
                success=False,
                error=str(e)
            )
            logger.error(f"OpenAI embedding API call failed: {e}", exc_info=True)
            
            # Map common OpenAI errors
            if "rate_limit" in str(e).lower():
                raise ExternalServiceException(
                    detail="OpenAI API rate limit exceeded",
                    service_name="OpenAI",
                    context={"error": "rate_limit", "retry_after": "60s"}
                )
            elif "insufficient_quota" in str(e).lower():
                raise ExternalServiceException(
                    detail="OpenAI API quota exceeded",
                    service_name="OpenAI",
                    context={"error": "quota_exceeded"}
                )
            else:
                raise ExternalServiceException(
                    detail="OpenAI embedding API request failed",
                    service_name="OpenAI",
                    context={"error": str(e)}
                )

    def is_healthy(self) -> bool:
        """Check if OpenAI embedding service is healthy."""
        try:
            return self._client is not None
        except Exception:
            return False