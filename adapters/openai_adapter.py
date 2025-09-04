"""
OpenAI API adapter for external service integration.
This handles all direct communication with OpenAI APIs.
"""

import asyncio
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
import json

from common.exceptions import (
    ExternalServiceException,
    ValidationException,
    BusinessLogicException
)
from common.logging import get_logger, log_performance

logger = get_logger("openai_adapter")


@dataclass
class AIRequest:
    """Base request for AI operations."""
    prompt: str
    max_tokens: Optional[int] = 1000
    temperature: Optional[float] = 0.1
    model: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


@dataclass
class AIResponse:
    """Response from AI operations."""
    content: str
    model_used: str
    tokens_used: int
    response_time_ms: float
    request_id: str
    metadata: Dict[str, Any]
    created_at: datetime


class BaseAIAdapter(ABC):
    """Abstract base class for AI service adapters."""

    @abstractmethod
    async def generate_text(self, request: AIRequest) -> AIResponse:
        """Generate text using AI model."""
        pass

    @abstractmethod
    async def generate_structured_response(self, request: AIRequest, schema: Dict[str, Any]) -> AIResponse:
        """Generate structured response using AI model."""
        pass

    @abstractmethod
    def is_healthy(self) -> bool:
        """Check if the AI service is healthy."""
        pass


class OpenAIAdapter(BaseAIAdapter):
    """
    OpenAI API adapter for text generation and structured responses.
    """

    def __init__(self, api_key: str, default_model: str = "gpt-3.5-turbo", timeout: int = 60):
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
            logger.info("OpenAI client initialized successfully")
        except ImportError:
            logger.error("OpenAI library not installed. Install with: pip install openai")
            raise BusinessLogicException(
                detail="OpenAI library not available",
                error_code="DEPENDENCY_MISSING"
            )
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            raise ExternalServiceException(
                detail="Failed to initialize OpenAI client",
                service_name="OpenAI",
                context={"error": str(e)}
            )

    async def generate_text(self, request: AIRequest) -> AIResponse:
        """Generate text using OpenAI API."""
        import time
        import uuid
        
        start_time = time.time()
        request_id = str(uuid.uuid4())
        
        try:
            # Validate request
            if not request.prompt or not request.prompt.strip():
                raise ValidationException(
                    detail="Prompt cannot be empty",
                    field="prompt",
                    value=request.prompt
                )
            
            # Prepare API call
            model = request.model or self.default_model
            messages = [{"role": "user", "content": request.prompt}]
            
            # Add context if provided
            if request.context:
                system_message = self._build_system_message(request.context)
                messages.insert(0, {"role": "system", "content": system_message})
            
            logger.debug(f"Making OpenAI API call with model: {model}")
            
            # Call OpenAI API
            response = await asyncio.wait_for(
                self._client.chat.completions.create(
                    model=model,
                    messages=messages,
                    max_tokens=request.max_tokens or 1000,
                    temperature=request.temperature or 0.1
                ),
                timeout=self.timeout
            )
            
            # Extract response data
            content = response.choices[0].message.content
            tokens_used = response.usage.total_tokens
            response_time_ms = (time.time() - start_time) * 1000
            
            # Create response object
            ai_response = AIResponse(
                content=content,
                model_used=response.model,
                tokens_used=tokens_used,
                response_time_ms=response_time_ms,
                request_id=request_id,
                metadata={
                    "completion_tokens": response.usage.completion_tokens,
                    "prompt_tokens": response.usage.prompt_tokens,
                    "finish_reason": response.choices[0].finish_reason
                },
                created_at=datetime.utcnow()
            )
            
            # Log performance
            log_performance(
                operation="openai_text_generation",
                duration_ms=response_time_ms,
                success=True,
                token_count=tokens_used
            )
            
            logger.info(f"OpenAI text generation completed: {tokens_used} tokens, {response_time_ms:.0f}ms")
            return ai_response
            
        except asyncio.TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="openai_text_generation",
                duration_ms=duration_ms,
                success=False,
                error="timeout"
            )
            raise ExternalServiceException(
                detail="OpenAI API request timed out",
                service_name="OpenAI",
                context={"timeout_seconds": self.timeout}
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="openai_text_generation",
                duration_ms=duration_ms,
                success=False,
                error=str(e)
            )
            logger.error(f"OpenAI API call failed: {e}", exc_info=True)
            
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
            elif "invalid_api_key" in str(e).lower():
                raise ExternalServiceException(
                    detail="Invalid OpenAI API key",
                    service_name="OpenAI",
                    context={"error": "authentication_failed"}
                )
            else:
                raise ExternalServiceException(
                    detail="OpenAI API request failed",
                    service_name="OpenAI",
                    context={"error": str(e)}
                )

    async def generate_structured_response(self, request: AIRequest, schema: Dict[str, Any]) -> AIResponse:
        """Generate structured response using OpenAI API with function calling."""
        import time
        import uuid
        
        start_time = time.time()
        request_id = str(uuid.uuid4())
        
        try:
            # Build function definition from schema
            function_definition = {
                "name": "generate_response",
                "description": "Generate a structured response",
                "parameters": schema
            }
            
            # Prepare API call with function calling
            model = request.model or self.default_model
            messages = [{"role": "user", "content": request.prompt}]
            
            if request.context:
                system_message = self._build_system_message(request.context)
                messages.insert(0, {"role": "system", "content": system_message})
            
            logger.debug(f"Making structured OpenAI API call with model: {model}")
            
            # Call OpenAI API with function calling
            response = await asyncio.wait_for(
                self._client.chat.completions.create(
                    model=model,
                    messages=messages,
                    functions=[function_definition],
                    function_call={"name": "generate_response"},
                    temperature=request.temperature or 0.1
                ),
                timeout=self.timeout
            )
            
            # Extract structured response
            function_call = response.choices[0].message.function_call
            if not function_call:
                raise ExternalServiceException(
                    detail="OpenAI did not return structured response",
                    service_name="OpenAI"
                )
            
            try:
                structured_content = json.loads(function_call.arguments)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse OpenAI function response: {e}")
                # Fall back to raw content
                structured_content = {"content": function_call.arguments}
            
            tokens_used = response.usage.total_tokens
            response_time_ms = (time.time() - start_time) * 1000
            
            # Create response object
            ai_response = AIResponse(
                content=json.dumps(structured_content),
                model_used=response.model,
                tokens_used=tokens_used,
                response_time_ms=response_time_ms,
                request_id=request_id,
                metadata={
                    "completion_tokens": response.usage.completion_tokens,
                    "prompt_tokens": response.usage.prompt_tokens,
                    "finish_reason": response.choices[0].finish_reason,
                    "function_used": True,
                    "structured_data": structured_content
                },
                created_at=datetime.utcnow()
            )
            
            log_performance(
                operation="openai_structured_generation",
                duration_ms=response_time_ms,
                success=True,
                token_count=tokens_used
            )
            
            logger.info(f"OpenAI structured generation completed: {tokens_used} tokens, {response_time_ms:.0f}ms")
            return ai_response
            
        except asyncio.TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="openai_structured_generation",
                duration_ms=duration_ms,
                success=False,
                error="timeout"
            )
            raise ExternalServiceException(
                detail="OpenAI API request timed out",
                service_name="OpenAI",
                context={"timeout_seconds": self.timeout}
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="openai_structured_generation",
                duration_ms=duration_ms,
                success=False,
                error=str(e)
            )
            logger.error(f"OpenAI structured API call failed: {e}", exc_info=True)
            raise ExternalServiceException(
                detail="OpenAI structured API request failed",
                service_name="OpenAI",
                context={"error": str(e)}
            )

    def _build_system_message(self, context: Dict[str, Any]) -> str:
        """Build system message from context."""
        system_parts = []
        
        if context.get("role"):
            system_parts.append(f"You are a {context['role']}.")
        
        if context.get("domain"):
            system_parts.append(f"You are working in the {context['domain']} compliance domain.")
        
        if context.get("instructions"):
            system_parts.append(context["instructions"])
        
        if context.get("format"):
            system_parts.append(f"Respond in {context['format']} format.")
        
        return " ".join(system_parts)

    def is_healthy(self) -> bool:
        """Check if OpenAI service is healthy."""
        try:
            # Simple health check by checking if client is initialized
            return self._client is not None
        except Exception:
            return False


class MockAIAdapter(BaseAIAdapter):
    """
    Mock AI adapter for testing and development.
    """

    def __init__(self, delay_ms: int = 100):
        self.delay_ms = delay_ms
        logger.info("Mock AI adapter initialized")

    async def generate_text(self, request: AIRequest) -> AIResponse:
        """Generate mock text response."""
        import time
        import uuid
        
        start_time = time.time()
        
        # Simulate API delay
        await asyncio.sleep(self.delay_ms / 1000)
        
        # Generate mock response based on prompt
        mock_content = self._generate_mock_content(request.prompt)
        
        response_time_ms = (time.time() - start_time) * 1000
        
        return AIResponse(
            content=mock_content,
            model_used="mock-gpt-3.5-turbo",
            tokens_used=len(mock_content.split()) * 2,  # Rough token estimate
            response_time_ms=response_time_ms,
            request_id=str(uuid.uuid4()),
            metadata={"mock": True, "delay_ms": self.delay_ms},
            created_at=datetime.utcnow()
        )

    async def generate_structured_response(self, request: AIRequest, schema: Dict[str, Any]) -> AIResponse:
        """Generate mock structured response."""
        import time
        import uuid
        
        start_time = time.time()
        
        # Simulate API delay
        await asyncio.sleep(self.delay_ms / 1000)
        
        # Generate mock structured response
        mock_structured = self._generate_mock_structured_content(request.prompt, schema)
        
        response_time_ms = (time.time() - start_time) * 1000
        
        return AIResponse(
            content=json.dumps(mock_structured),
            model_used="mock-gpt-3.5-turbo",
            tokens_used=100,
            response_time_ms=response_time_ms,
            request_id=str(uuid.uuid4()),
            metadata={"mock": True, "structured_data": mock_structured},
            created_at=datetime.utcnow()
        )

    def _generate_mock_content(self, prompt: str) -> str:
        """Generate mock content based on prompt."""
        if "recommendation" in prompt.lower():
            return "Based on the compliance gap analysis, I recommend implementing a comprehensive policy framework with the following key components: 1) Clear documentation of procedures, 2) Regular training for staff, 3) Monitoring and audit mechanisms, and 4) Regular review and update cycles."
        elif "gap" in prompt.lower():
            return "The identified compliance gap indicates a missing or inadequate control in your current framework. This requires immediate attention to ensure regulatory compliance and minimize business risk."
        else:
            return f"This is a mock AI response to your query: '{prompt[:50]}...'. In a real implementation, this would be generated by OpenAI's language models."

    def _generate_mock_structured_content(self, prompt: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate mock structured content."""
        mock_response = {}
        
        # Generate mock data based on schema properties
        properties = schema.get("properties", {})
        
        for field, field_schema in properties.items():
            field_type = field_schema.get("type", "string")
            
            if field == "recommendation_text":
                mock_response[field] = "Mock recommendation: Implement additional controls"
            elif field == "recommended_actions":
                mock_response[field] = ["Review current policies", "Update procedures", "Train staff"]
            elif field == "risk_level":
                mock_response[field] = "medium"
            elif field == "implementation_priority":
                mock_response[field] = "high"
            elif field_type == "string":
                mock_response[field] = f"Mock {field}"
            elif field_type == "array":
                mock_response[field] = [f"Mock item 1", f"Mock item 2"]
            elif field_type == "number":
                mock_response[field] = 42
            elif field_type == "boolean":
                mock_response[field] = True
            else:
                mock_response[field] = f"Mock {field}"
        
        return mock_response

    def is_healthy(self) -> bool:
        """Mock adapter is always healthy."""
        return True