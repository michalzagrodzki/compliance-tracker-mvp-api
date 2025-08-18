"""
AI Service layer for business logic around AI operations.
This layer handles caching, rate limiting, and business rules.
"""

import asyncio
import hashlib
import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import asdict

from adapters.openai_adapter import BaseAIAdapter, AIRequest, AIResponse
from common.exceptions import (
    ExternalServiceException,
    ValidationException,
    BusinessLogicException,
    ResourceNotFoundException
)
from common.logging import get_logger, log_business_event, log_performance

logger = get_logger("ai_service")


class AICache:
    """Simple in-memory cache for AI responses."""
    
    def __init__(self, ttl_minutes: int = 60):
        self._cache = {}
        self.ttl_minutes = ttl_minutes
    
    def _generate_key(self, request: AIRequest) -> str:
        """Generate cache key from request."""
        # Create a hash of the request parameters
        request_data = {
            "prompt": request.prompt,
            "model": request.model,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "context": request.context
        }
        request_json = json.dumps(request_data, sort_keys=True)
        return hashlib.md5(request_json.encode()).hexdigest()
    
    def get(self, request: AIRequest) -> Optional[AIResponse]:
        """Get cached response if available and not expired."""
        key = self._generate_key(request)
        
        if key in self._cache:
            response, cached_at = self._cache[key]
            
            # Check if cache entry is still valid
            if datetime.utcnow() - cached_at < timedelta(minutes=self.ttl_minutes):
                logger.debug(f"Cache hit for AI request: {key[:8]}...")
                return response
            else:
                # Remove expired entry
                del self._cache[key]
        
        return None
    
    def set(self, request: AIRequest, response: AIResponse) -> None:
        """Cache the response."""
        key = self._generate_key(request)
        self._cache[key] = (response, datetime.utcnow())
        logger.debug(f"Cached AI response: {key[:8]}...")
    
    def clear(self) -> None:
        """Clear all cached responses."""
        self._cache.clear()
        logger.info("AI cache cleared")
    
    def size(self) -> int:
        """Get number of cached entries."""
        return len(self._cache)


class AIService:
    """
    AI Service for handling AI operations with business logic.
    Provides caching, rate limiting, and error handling.
    """

    def __init__(self, ai_adapter: BaseAIAdapter, enable_cache: bool = True, cache_ttl_minutes: int = 60):
        self.ai_adapter = ai_adapter
        self.enable_cache = enable_cache
        self.cache = AICache(cache_ttl_minutes) if enable_cache else None
        self._request_count = 0
        self._last_request_time = None

    async def generate_text(
        self, 
        prompt: str, 
        context: Optional[Dict[str, Any]] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        user_id: Optional[str] = None,
        use_cache: bool = True
    ) -> AIResponse:
        """Generate text with business logic and caching."""
        try:
            import time
            start_time = time.time()
            
            # Validate input
            if not prompt or not prompt.strip():
                raise ValidationException(
                    detail="Prompt cannot be empty",
                    field="prompt",
                    value=prompt
                )
            
            # Create AI request
            ai_request = AIRequest(
                prompt=prompt.strip(),
                context=context,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens
            )
            
            # Check cache first
            if self.enable_cache and use_cache and self.cache:
                cached_response = self.cache.get(ai_request)
                if cached_response:
                    # Log cache hit
                    log_business_event(
                        event_type="AI_CACHE_HIT",
                        entity_type="ai_request",
                        entity_id="cached",
                        action="retrieve",
                        user_id=user_id,
                        details={"prompt_length": len(prompt)}
                    )
                    return cached_response
            
            # Rate limiting check
            self._check_rate_limit()
            
            # Call AI adapter
            response = await self.ai_adapter.generate_text(ai_request)
            
            # Cache the response
            if self.enable_cache and use_cache and self.cache:
                self.cache.set(ai_request, response)
            
            # Log business event
            log_business_event(
                event_type="AI_TEXT_GENERATED",
                entity_type="ai_request",
                entity_id=response.request_id,
                action="generate",
                user_id=user_id,
                details={
                    "model_used": response.model_used,
                    "tokens_used": response.tokens_used,
                    "prompt_length": len(prompt),
                    "response_length": len(response.content),
                    "cached": False
                }
            )
            
            # Update request tracking
            self._update_request_tracking()
            
            return response
            
        except (ValidationException, ExternalServiceException):
            raise
        except Exception as e:
            logger.error(f"AI text generation failed: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="AI text generation failed",
                error_code="AI_GENERATION_FAILED",
                context={"error": str(e)}
            )

    async def generate_structured_response(
        self,
        prompt: str,
        response_schema: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        model: Optional[str] = None,
        user_id: Optional[str] = None,
        use_cache: bool = True
    ) -> Dict[str, Any]:
        """Generate structured response with validation."""
        try:
            # Validate input
            if not prompt or not prompt.strip():
                raise ValidationException(
                    detail="Prompt cannot be empty",
                    field="prompt",
                    value=prompt
                )
            
            if not response_schema:
                raise ValidationException(
                    detail="Response schema cannot be empty",
                    field="response_schema",
                    value=response_schema
                )
            
            # Create AI request
            ai_request = AIRequest(
                prompt=prompt.strip(),
                context=context,
                model=model,
                temperature=0.3  # Lower temperature for structured responses
            )
            
            # Check cache first
            if self.enable_cache and use_cache and self.cache:
                cached_response = self.cache.get(ai_request)
                if cached_response:
                    try:
                        return json.loads(cached_response.content)
                    except json.JSONDecodeError:
                        # Invalid cached data, proceed with fresh request
                        pass
            
            # Rate limiting check
            self._check_rate_limit()
            
            # Call AI adapter for structured response
            response = await self.ai_adapter.generate_structured_response(ai_request, response_schema)
            
            # Parse and validate structured response
            try:
                structured_data = json.loads(response.content)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse AI structured response: {e}")
                raise BusinessLogicException(
                    detail="AI returned invalid structured response",
                    error_code="AI_INVALID_STRUCTURE",
                    context={"response": response.content[:200]}
                )
            
            # Validate against schema (basic validation)
            self._validate_structured_response(structured_data, response_schema)
            
            # Cache the response
            if self.enable_cache and use_cache and self.cache:
                self.cache.set(ai_request, response)
            
            # Log business event
            log_business_event(
                event_type="AI_STRUCTURED_GENERATED",
                entity_type="ai_request",
                entity_id=response.request_id,
                action="generate",
                user_id=user_id,
                details={
                    "model_used": response.model_used,
                    "tokens_used": response.tokens_used,
                    "schema_fields": list(response_schema.get("properties", {}).keys()),
                    "cached": False
                }
            )
            
            # Update request tracking
            self._update_request_tracking()
            
            return structured_data
            
        except (ValidationException, ExternalServiceException, BusinessLogicException):
            raise
        except Exception as e:
            logger.error(f"AI structured generation failed: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="AI structured generation failed",
                error_code="AI_STRUCTURED_GENERATION_FAILED",
                context={"error": str(e)}
            )

    async def analyze_text_sentiment(self, text: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Analyze sentiment of text."""
        prompt = f"""
        Analyze the sentiment of the following text and provide a structured response.
        
        Text: "{text}"
        
        Provide sentiment analysis including:
        - Overall sentiment (positive, negative, neutral)
        - Confidence score (0.0 to 1.0)
        - Key emotional indicators
        """
        
        schema = {
            "type": "object",
            "properties": {
                "sentiment": {
                    "type": "string",
                    "enum": ["positive", "negative", "neutral"]
                },
                "confidence_score": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0
                },
                "emotional_indicators": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
            "required": ["sentiment", "confidence_score"]
        }
        
        return await self.generate_structured_response(
            prompt=prompt,
            response_schema=schema,
            user_id=user_id
        )

    async def summarize_text(
        self, 
        text: str, 
        max_length: int = 200, 
        user_id: Optional[str] = None
    ) -> str:
        """Generate a summary of text."""
        prompt = f"""
        Provide a concise summary of the following text in approximately {max_length} characters.
        
        Text: "{text}"
        
        Summary:
        """
        
        context = {
            "role": "text summarizer",
            "instructions": f"Provide a clear, concise summary in approximately {max_length} characters."
        }
        
        response = await self.generate_text(
            prompt=prompt,
            context=context,
            max_tokens=max_length // 3,  # Rough token estimate
            user_id=user_id
        )
        
        return response.content.strip()

    def _check_rate_limit(self) -> None:
        """Check if rate limiting should be applied."""
        # Simple rate limiting: max 100 requests per minute
        now = datetime.utcnow()
        
        if self._last_request_time and now - self._last_request_time < timedelta(minutes=1):
            if self._request_count >= 100:
                raise BusinessLogicException(
                    detail="AI service rate limit exceeded",
                    error_code="AI_RATE_LIMIT_EXCEEDED",
                    context={"limit": "100 requests per minute"}
                )
        else:
            # Reset counter for new minute window
            self._request_count = 0
            self._last_request_time = now

    def _update_request_tracking(self) -> None:
        """Update request tracking."""
        self._request_count += 1
        self._last_request_time = datetime.utcnow()

    def _validate_structured_response(self, data: Dict[str, Any], schema: Dict[str, Any]) -> None:
        """Basic validation of structured response against schema."""
        required_fields = schema.get("required", [])
        properties = schema.get("properties", {})
        
        # Check required fields
        for field in required_fields:
            if field not in data:
                raise ValidationException(
                    detail=f"Required field missing from AI response: {field}",
                    field=field,
                    value=None
                )
        
        # Basic type checking
        for field, value in data.items():
            if field in properties:
                expected_type = properties[field].get("type")
                if expected_type == "string" and not isinstance(value, str):
                    logger.warning(f"AI response field {field} should be string but got {type(value)}")
                elif expected_type == "number" and not isinstance(value, (int, float)):
                    logger.warning(f"AI response field {field} should be number but got {type(value)}")
                elif expected_type == "array" and not isinstance(value, list):
                    logger.warning(f"AI response field {field} should be array but got {type(value)}")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if not self.cache:
            return {"cache_enabled": False}
        
        return {
            "cache_enabled": True,
            "cache_size": self.cache.size(),
            "ttl_minutes": self.cache.ttl_minutes
        }

    def clear_cache(self) -> None:
        """Clear AI response cache."""
        if self.cache:
            self.cache.clear()
            logger.info("AI service cache cleared")

    def is_healthy(self) -> bool:
        """Check if AI service is healthy."""
        return self.ai_adapter.is_healthy()


# Factory function
def create_ai_service(ai_adapter: BaseAIAdapter, enable_cache: bool = True) -> AIService:
    """Factory function to create AIService instance."""
    return AIService(ai_adapter, enable_cache)