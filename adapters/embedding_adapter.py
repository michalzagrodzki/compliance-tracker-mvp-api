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

from common.exceptions import (
    ExternalServiceException,
    ValidationException,
    BusinessLogicException
)
from common.logging import get_logger, log_performance

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
    async def generate_batch_embeddings(self, requests: List[EmbeddingRequest]) -> List[EmbeddingResponse]:
        """Generate embeddings for multiple texts."""
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """Check if the embedding service is healthy."""
        pass


class OpenAIEmbeddingAdapter(BaseEmbeddingAdapter):
    """
    OpenAI embedding adapter for text embedding generation.
    """

    def __init__(self, api_key: str, default_model: str = "text-embedding-3-small", timeout: int = 30):
        self.api_key = api_key
        self.default_model = default_model
        self.timeout = timeout
        self._client = None
        self._initialize_client()

    def _initialize_client(self):
        """Initialize OpenAI client."""
        try:
            import openai
            self._client = openai.AsyncOpenAI(api_key=self.api_key)
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
            token_count = response.usage.total_tokens
            response_time_ms = (time.time() - start_time) * 1000
            
            # Create response object
            embedding_response = EmbeddingResponse(
                embedding=embedding,
                model_used=response.model,
                token_count=token_count,
                response_time_ms=response_time_ms,
                request_id=request_id,
                metadata={
                    "prompt_tokens": response.usage.prompt_tokens,
                    "total_tokens": response.usage.total_tokens,
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

    async def generate_batch_embeddings(self, requests: List[EmbeddingRequest]) -> List[EmbeddingResponse]:
        """Generate embeddings for multiple texts using OpenAI API."""
        import uuid
        
        if not requests:
            return []
        
        start_time = time.time()
        request_id = str(uuid.uuid4())
        
        try:
            # Validate all requests
            texts = []
            for i, request in enumerate(requests):
                if not request.text or not request.text.strip():
                    raise ValidationException(
                        detail=f"Text at index {i} cannot be empty",
                        field=f"requests[{i}].text",
                        value=request.text
                    )
                texts.append(request.text.strip())
            
            # Use model from first request or default
            model = requests[0].model or self.default_model
            
            logger.debug(f"Making OpenAI batch embedding API call with model: {model}, batch_size: {len(texts)}")
            
            # Call OpenAI API with batch
            response = await asyncio.wait_for(
                self._client.embeddings.create(
                    model=model,
                    input=texts
                ),
                timeout=self.timeout * len(texts)  # Scale timeout with batch size
            )
            
            # Extract response data
            response_time_ms = (time.time() - start_time) * 1000
            
            # Create response objects
            embedding_responses = []
            for i, data in enumerate(response.data):
                embedding_response = EmbeddingResponse(
                    embedding=data.embedding,
                    model_used=response.model,
                    token_count=response.usage.total_tokens // len(response.data),  # Approximate per-text tokens
                    response_time_ms=response_time_ms,
                    request_id=f"{request_id}-{i}",
                    metadata={
                        "batch_index": i,
                        "batch_size": len(texts),
                        "text_length": len(texts[i]),
                        "embedding_dimensions": len(data.embedding),
                        "total_batch_tokens": response.usage.total_tokens
                    },
                    created_at=datetime.utcnow()
                )
                embedding_responses.append(embedding_response)
            
            # Log performance
            log_performance(
                operation="openai_batch_embedding_generation",
                duration_ms=response_time_ms,
                success=True,
                token_count=response.usage.total_tokens,
                item_count=len(texts)
            )
            
            logger.info(f"OpenAI batch embedding generation completed: {len(texts)} texts, {response.usage.total_tokens} tokens, {response_time_ms:.0f}ms")
            return embedding_responses
            
        except asyncio.TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="openai_batch_embedding_generation",
                duration_ms=duration_ms,
                success=False,
                error="timeout"
            )
            raise ExternalServiceException(
                detail="OpenAI batch embedding API request timed out",
                service_name="OpenAI",
                context={"timeout_seconds": self.timeout, "batch_size": len(requests)}
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="openai_batch_embedding_generation",
                duration_ms=duration_ms,
                success=False,
                error=str(e)
            )
            logger.error(f"OpenAI batch embedding API call failed: {e}", exc_info=True)
            raise ExternalServiceException(
                detail="OpenAI batch embedding API request failed",
                service_name="OpenAI",
                context={"error": str(e), "batch_size": len(requests)}
            )

    def is_healthy(self) -> bool:
        """Check if OpenAI embedding service is healthy."""
        try:
            return self._client is not None
        except Exception:
            return False


class MockEmbeddingAdapter(BaseEmbeddingAdapter):
    """
    Mock embedding adapter for testing and development.
    """

    def __init__(self, delay_ms: int = 50, dimensions: int = 1536):
        self.delay_ms = delay_ms
        self.dimensions = dimensions
        logger.info("Mock embedding adapter initialized")

    async def generate_embedding(self, request: EmbeddingRequest) -> EmbeddingResponse:
        """Generate mock embedding."""
        import uuid
        import random
        
        start_time = time.time()
        
        # Simulate API delay
        await asyncio.sleep(self.delay_ms / 1000)
        
        # Generate mock embedding (normalized random vector)
        embedding = [random.gauss(0, 0.5) for _ in range(self.dimensions)]
        # Normalize the vector
        magnitude = sum(x*x for x in embedding) ** 0.5
        embedding = [x / magnitude for x in embedding]
        
        response_time_ms = (time.time() - start_time) * 1000
        
        return EmbeddingResponse(
            embedding=embedding,
            model_used="mock-text-embedding-3-small",
            token_count=len(request.text.split()),  # Rough token estimate
            response_time_ms=response_time_ms,
            request_id=str(uuid.uuid4()),
            metadata={
                "mock": True, 
                "delay_ms": self.delay_ms,
                "dimensions": self.dimensions,
                "text_length": len(request.text)
            },
            created_at=datetime.utcnow()
        )

    async def generate_batch_embeddings(self, requests: List[EmbeddingRequest]) -> List[EmbeddingResponse]:
        """Generate batch mock embeddings."""
        if not requests:
            return []
        
        # Generate embeddings concurrently
        tasks = [self.generate_embedding(request) for request in requests]
        return await asyncio.gather(*tasks)

    def is_healthy(self) -> bool:
        """Mock adapter is always healthy."""
        return True