"""
Middleware for error handling, logging, and request tracking.
"""

import time
import uuid
from typing import Callable, Dict, Any
from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from pydantic import ValidationError

from common.exceptions import BaseRAGException
from common.logging import (
    RequestContextLogger, 
    log_api_request, 
    log_error, 
    log_security_event,
    get_logger
)
from common.responses import (
    create_error_response,
    create_validation_error_response,
    create_service_unavailable_response
)


class RequestTrackingMiddleware(BaseHTTPMiddleware):
    """Middleware for tracking requests with correlation IDs and logging."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.logger = get_logger("middleware")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip middleware processing for documentation endpoints
        path = str(request.url.path)
        if path in ["/docs", "/redoc", "/openapi.json"] or path.startswith("/docs/") or path.startswith("/redoc/"):
            return await call_next(request)
        
        # Generate request ID
        request_id = str(uuid.uuid4())
        
        # Extract user info from request if available
        user_id = None
        audit_session_id = None
        
        # Try to extract user info from authorization header or validated user
        if hasattr(request.state, 'user'):
            user_id = getattr(request.state.user, 'id', None)
        
        # Try to extract audit session from query params or body
        if request.method == "GET":
            audit_session_id = request.query_params.get('audit_session_id')
        
        # Start timing
        start_time = time.time()
        
        # Set up logging context
        with RequestContextLogger(
            request_id=request_id,
            user_id=user_id,
            audit_session_id=audit_session_id
        ):
            try:
                # Add request ID to state for access in handlers
                request.state.request_id = request_id
                
                # Process request
                response = await call_next(request)
                
                # Calculate duration
                duration_ms = (time.time() - start_time) * 1000
                
                # Log successful API request
                log_api_request(
                    method=request.method,
                    path=str(request.url.path),
                    status_code=response.status_code,
                    duration_ms=duration_ms,
                    user_id=user_id,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent")
                )
                
                # Add request ID to response headers
                response.headers["X-Request-ID"] = request_id
                
                return response
                
            except Exception as e:
                # Calculate duration
                duration_ms = (time.time() - start_time) * 1000
                
                # Log error
                log_error(e, context={
                    "method": request.method,
                    "path": str(request.url.path),
                    "duration_ms": duration_ms
                }, user_id=user_id)
                
                # Log API request with error status
                log_api_request(
                    method=request.method,
                    path=str(request.url.path),
                    status_code=500,
                    duration_ms=duration_ms,
                    user_id=user_id,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent")
                )
                
                # Re-raise to be handled by error handler
                raise


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """Middleware for centralized error handling and response formatting."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.logger = get_logger("error_handler")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            response = await call_next(request)
            return response
        except BaseRAGException as e:
            # Handle custom RAG exceptions
            return self._handle_rag_exception(e, request)
        except HTTPException as e:
            # Handle FastAPI HTTP exceptions
            return self._handle_http_exception(e, request)
        except ValidationError as e:
            # Handle Pydantic validation errors
            return self._handle_validation_error(e, request)
        except Exception as e:
            # Handle unexpected errors
            return self._handle_unexpected_error(e, request)
    
    def _handle_rag_exception(self, error: BaseRAGException, request: Request) -> JSONResponse:
        """Handle custom RAG exceptions."""
        self.logger.error(
            f"RAG exception: {error.error_code}",
            extra={
                "error_code": error.error_code,
                "status_code": error.status_code,
                "context": error.context,
                "path": str(request.url.path),
                "method": request.method
            }
        )
        
        response = create_error_response(
            error_code=error.error_code,
            message=error.detail,
            status_code=error.status_code,
            context=error.context
        )
        
        # Add any custom headers
        if error.headers:
            for key, value in error.headers.items():
                response.headers[key] = value
        
        return response
    
    def _handle_http_exception(self, error: HTTPException, request: Request) -> JSONResponse:
        """Handle FastAPI HTTP exceptions."""
        self.logger.warning(
            f"HTTP exception: {error.status_code}",
            extra={
                "status_code": error.status_code,
                "detail": error.detail,
                "path": str(request.url.path),
                "method": request.method
            }
        )
        
        # Map common HTTP status codes to error codes
        error_code_map = {
            400: "BAD_REQUEST",
            401: "AUTHENTICATION_REQUIRED",
            403: "ACCESS_DENIED",
            404: "RESOURCE_NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            409: "RESOURCE_CONFLICT",
            429: "RATE_LIMIT_EXCEEDED",
            500: "INTERNAL_SERVER_ERROR",
            502: "BAD_GATEWAY",
            503: "SERVICE_UNAVAILABLE",
            504: "GATEWAY_TIMEOUT"
        }
        
        error_code = error_code_map.get(error.status_code, "HTTP_ERROR")
        
        response = create_error_response(
            error_code=error_code,
            message=error.detail,
            status_code=error.status_code
        )
        
        # Add any custom headers
        if error.headers:
            for key, value in error.headers.items():
                response.headers[key] = value
        
        return response
    
    def _handle_validation_error(self, error: ValidationError, request: Request) -> JSONResponse:
        """Handle Pydantic validation errors."""
        self.logger.warning(
            "Validation error occurred",
            extra={
                "error_count": error.error_count(),
                "path": str(request.url.path),
                "method": request.method
            }
        )
        
        # Format validation errors
        validation_errors = []
        for err in error.errors():
            validation_errors.append({
                "field": ".".join(str(x) for x in err["loc"]),
                "message": err["msg"],
                "type": err["type"],
                "value": err.get("input")
            })
        
        return create_validation_error_response(
            validation_errors=validation_errors,
            message="Request validation failed"
        )
    
    def _handle_unexpected_error(self, error: Exception, request: Request) -> JSONResponse:
        """Handle unexpected errors."""
        self.logger.error(
            f"Unexpected error: {type(error).__name__}",
            extra={
                "error_type": type(error).__name__,
                "error_message": str(error),
                "path": str(request.url.path),
                "method": request.method
            },
            exc_info=True
        )
        
        # Don't expose internal error details in production
        return create_error_response(
            error_code="INTERNAL_SERVER_ERROR",
            message="An unexpected error occurred",
            status_code=500
        )


class SecurityMiddleware(BaseHTTPMiddleware):
    """Middleware for security headers and basic security checks."""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.logger = get_logger("security")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip security checks for documentation endpoints
        path = str(request.url.path)
        if path in ["/docs", "/redoc", "/openapi.json"] or path.startswith("/docs/") or path.startswith("/redoc/"):
            response = await call_next(request)
            # Still add basic security headers but skip the strict checks
            self._add_basic_security_headers(response)
            return response
        
        # Basic security checks
        await self._check_request_security(request)
        
        # Process request
        response = await call_next(request)
        
        # Add security headers
        self._add_security_headers(response)
        
        return response
    
    async def _check_request_security(self, request: Request) -> None:
        """Perform basic security checks on the request."""
        # Check for suspicious patterns in path
        path = str(request.url.path)
        suspicious_patterns = [
            "../", "..\\", "<script", "javascript:", "data:",
            "vbscript:", "onload=", "onerror=", "eval(", "document.cookie"
        ]
        
        for pattern in suspicious_patterns:
            if pattern.lower() in path.lower():
                log_security_event(
                    event_type="SUSPICIOUS_PATH",
                    ip_address=request.client.host if request.client else None,
                    details={"path": path, "pattern": pattern}
                )
                break
        
        # Check request size (basic DoS protection)
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > 100 * 1024 * 1024:  # 100MB
            log_security_event(
                event_type="LARGE_REQUEST",
                ip_address=request.client.host if request.client else None,
                details={"content_length": content_length}
            )
        
        # Check for common attack headers
        dangerous_headers = ["x-forwarded-host", "x-real-ip", "x-originating-ip"]
        for header in dangerous_headers:
            if header in request.headers:
                log_security_event(
                    event_type="SUSPICIOUS_HEADER",
                    ip_address=request.client.host if request.client else None,
                    details={"header": header, "value": request.headers[header]}
                )
    
    def _add_security_headers(self, response: Response) -> None:
        """Add security headers to the response."""
        security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
    
    def _add_basic_security_headers(self, response: Response) -> None:
        """Add basic security headers for documentation endpoints."""
        basic_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",  # Less restrictive for docs
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }
        
        for header, value in basic_headers.items():
            response.headers[header] = value


def setup_middleware(app) -> None:
    """Setup all middleware for the application."""
    # Add middleware in reverse order (last added is executed first)
    app.add_middleware(ErrorHandlingMiddleware)
    app.add_middleware(SecurityMiddleware)
    app.add_middleware(RequestTrackingMiddleware)