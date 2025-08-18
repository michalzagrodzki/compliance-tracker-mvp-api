"""
Embeddings adapter interface and implementations for the adapter pattern.
This decouples our vector-store pipeline from a concrete provider (OpenAI).
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import List, Optional

from common.exceptions import ExternalServiceException, BusinessLogicException
from common.logging import get_logger, log_performance

logger = get_logger("embeddings_adapter")


class BaseEmbeddingsAdapter(ABC):
    @abstractmethod
    def is_healthy(self) -> bool:
        pass

    @abstractmethod
    def embed_texts(self, texts: List[str], model: Optional[str] = None, batch_size: int = 64) -> List[List[float]]:
        """Synchronously embed a batch of texts and return vectors."""
        pass

    @abstractmethod
    def embed_query(self, text: str, model: Optional[str] = None) -> List[float]:
        """Synchronously embed a single text (query)."""
        pass


class OpenAIEmbeddingsAdapter(BaseEmbeddingsAdapter):
    """
    OpenAI embeddings adapter. Uses the official OpenAI Python SDK (v1 style).
    Provides batching, basic retry, and performance logging.
    """

    def __init__(self, api_key: str, default_model: str = "text-embedding-3-small", timeout: int = 60):
        self.api_key = api_key
        self.default_model = default_model
        self.timeout = timeout
        self._client = None
        self._init_client()

    def _init_client(self):
        try:
            import openai
            self._client = openai.OpenAI(api_key=self.api_key)
        except ImportError:
            raise BusinessLogicException(detail="openai package not installed", error_code="DEPENDENCY_MISSING")

    def is_healthy(self) -> bool:
        return self._client is not None

    def embed_texts(self, texts: List[str], model: Optional[str] = None, batch_size: int = 64) -> List[List[float]]:
        import time
        model = model or self.default_model
        vectors: List[List[float]] = []
        start = time.time()

        try:
            for i in range(0, len(texts), batch_size):
                batch = texts[i : i + batch_size]
                resp = self._client.embeddings.create(model=model, input=batch, timeout=self.timeout)
                # Ensure ordering aligns with inputs
                vectors.extend([item.embedding for item in resp.data])
            duration_ms = (time.time() - start) * 1000
            log_performance("openai_embeddings_batch", duration_ms, success=True, item_count=len(texts))
            return vectors
        except Exception as e:
            duration_ms = (time.time() - start) * 1000
            log_performance("openai_embeddings_batch", duration_ms, success=False, error=str(e))
            raise ExternalServiceException(detail="OpenAI embeddings failed", service_name="OpenAI", context={"error": str(e)})

    def embed_query(self, text: str, model: Optional[str] = None) -> List[float]:
        return self.embed_texts([text], model=model, batch_size=1)[0]


class MockEmbeddingsAdapter(BaseEmbeddingsAdapter):
    """Mock embeddings adapter for tests/dev without network access."""

    def __init__(self, dim: int = 1536):
        self.dim = dim

    def is_healthy(self) -> bool:
        return True

    def embed_texts(self, texts: List[str], model: Optional[str] = None, batch_size: int = 64) -> List[List[float]]:
        # Simple deterministic hash-based vectors for stability in tests
        def vec(t: str) -> List[float]:
            import hashlib
            h = hashlib.md5(t.encode()).digest()
            # Expand hash deterministically to desired dim
            base = list(h)
            out = []
            while len(out) < self.dim:
                out.extend(base)
            return [float(v) / 255.0 for v in out[: self.dim]]

        return [vec(t) for t in texts]

    def embed_query(self, text: str, model: Optional[str] = None) -> List[float]:
        return self.embed_texts([text])[0]

