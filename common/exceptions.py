"""
Centralized exception classes for the RAG application.
Provides a hierarchy of custom exceptions with proper error codes and messages.
"""

from typing import Optional, Dict, Any
from fastapi import HTTPException, status


class BaseRAGException(HTTPException):
    """Base exception class for all RAG application errors."""
    
    def __init__(
        self,
        detail: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        headers: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}


# Authentication & Authorization Exceptions
class AuthenticationException(BaseRAGException):
    """Authentication-related errors."""
    
    def __init__(
        self,
        detail: str = "Authentication failed",
        error_code: str = "AUTH_FAILED",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_401_UNAUTHORIZED,
            error_code=error_code,
            context=context
        )


class AuthorizationException(BaseRAGException):
    """Authorization-related errors."""
    
    def __init__(
        self,
        detail: str = "Access denied",
        error_code: str = "ACCESS_DENIED",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_403_FORBIDDEN,
            error_code=error_code,
            context=context
        )


class InvalidTokenException(AuthenticationException):
    """Invalid or expired token errors."""
    
    def __init__(
        self,
        detail: str = "Invalid or expired token",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            error_code="INVALID_TOKEN",
            context=context
        )


class InsufficientPermissionsException(AuthorizationException):
    """Insufficient permissions errors."""
    
    def __init__(
        self,
        required_roles: Optional[list] = None,
        user_role: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        detail = "Insufficient permissions"
        if required_roles and user_role:
            detail = f"Required roles: {required_roles}, user role: {user_role}"
        
        super().__init__(
            detail=detail,
            error_code="INSUFFICIENT_PERMISSIONS",
            context=context or {"required_roles": required_roles, "user_role": user_role}
        )


# Validation Exceptions
class ValidationException(BaseRAGException):
    """Data validation errors."""
    
    def __init__(
        self,
        detail: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code="VALIDATION_ERROR",
            context=context or {"field": field, "value": value}
        )


class InvalidUUIDException(ValidationException):
    """Invalid UUID format errors."""
    
    def __init__(
        self,
        field: str,
        value: str,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=f"Invalid UUID format for field '{field}': {value}",
            field=field,
            value=value,
            context=context
        )


class InvalidFileException(ValidationException):
    """Invalid file upload errors."""
    
    def __init__(
        self,
        detail: str,
        filename: Optional[str] = None,
        file_type: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            context=context or {"filename": filename, "file_type": file_type}
        )


# Resource Exceptions
class ResourceException(BaseRAGException):
    """Resource-related errors."""
    
    def __init__(
        self,
        detail: str,
        status_code: int = status.HTTP_404_NOT_FOUND,
        error_code: str = "RESOURCE_ERROR",
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            status_code=status_code,
            error_code=error_code,
            context=context or {"resource_type": resource_type, "resource_id": resource_id}
        )


class ResourceNotFoundException(ResourceException):
    """Resource not found errors."""
    
    def __init__(
        self,
        resource_type: str,
        resource_id: str,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=f"{resource_type} with ID '{resource_id}' not found",
            status_code=status.HTTP_404_NOT_FOUND,
            error_code="RESOURCE_NOT_FOUND",
            resource_type=resource_type,
            resource_id=resource_id,
            context=context
        )


class ResourceConflictException(ResourceException):
    """Resource conflict errors."""
    
    def __init__(
        self,
        detail: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_409_CONFLICT,
            error_code="RESOURCE_CONFLICT",
            resource_type=resource_type,
            resource_id=resource_id,
            context=context
        )


class ResourceLimitExceededException(ResourceException):
    """Resource limit exceeded errors."""
    
    def __init__(
        self,
        resource_type: str,
        limit: int,
        current: int,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=f"{resource_type} limit exceeded: {current}/{limit}",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error_code="RESOURCE_LIMIT_EXCEEDED",
            resource_type=resource_type,
            context=context or {"limit": limit, "current": current}
        )


# Business Logic Exceptions
class BusinessLogicException(BaseRAGException):
    """Business logic errors."""
    
    def __init__(
        self,
        detail: str,
        error_code: str = "BUSINESS_LOGIC_ERROR",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_400_BAD_REQUEST,
            error_code=error_code,
            context=context
        )


class ComplianceDomainMismatchException(BusinessLogicException):
    """Compliance domain mismatch errors."""
    
    def __init__(
        self,
        expected_domain: str,
        actual_domain: str,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=f"Compliance domain mismatch: expected '{expected_domain}', got '{actual_domain}'",
            error_code="COMPLIANCE_DOMAIN_MISMATCH",
            context=context or {"expected_domain": expected_domain, "actual_domain": actual_domain}
        )


class AuditSessionMismatchException(BusinessLogicException):
    """Audit session mismatch errors."""
    
    def __init__(
        self,
        expected_session: str,
        actual_session: str,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=f"Audit session mismatch: expected '{expected_session}', got '{actual_session}'",
            error_code="AUDIT_SESSION_MISMATCH",
            context=context or {"expected_session": expected_session, "actual_session": actual_session}
        )


class InactiveAuditSessionException(BusinessLogicException):
    """Inactive audit session errors."""
    
    def __init__(
        self,
        session_id: str,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=f"Audit session '{session_id}' is not active",
            error_code="INACTIVE_AUDIT_SESSION",
            context=context or {"session_id": session_id}
        )


# External Service Exceptions
class ExternalServiceException(BaseRAGException):
    """External service errors."""
    
    def __init__(
        self,
        detail: str,
        service_name: str,
        error_code: str = "EXTERNAL_SERVICE_ERROR",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            error_code=error_code,
            context=context or {"service_name": service_name}
        )


class DatabaseException(ExternalServiceException):
    """Database-related errors."""
    
    def __init__(
        self,
        detail: str,
        operation: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            service_name="database",
            error_code="DATABASE_ERROR",
            context=context or {"operation": operation}
        )


class OpenAIException(ExternalServiceException):
    """OpenAI API errors."""
    
    def __init__(
        self,
        detail: str,
        model: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            service_name="openai",
            error_code="OPENAI_ERROR",
            context=context or {"model": model}
        )


class SupabaseException(ExternalServiceException):
    """Supabase errors."""
    
    def __init__(
        self,
        detail: str,
        table: Optional[str] = None,
        operation: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            service_name="supabase",
            error_code="SUPABASE_ERROR",
            context=context or {"table": table, "operation": operation}
        )


# File Processing Exceptions
class FileProcessingException(BaseRAGException):
    """File processing errors."""
    
    def __init__(
        self,
        detail: str,
        filename: Optional[str] = None,
        error_code: str = "FILE_PROCESSING_ERROR",
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            error_code=error_code,
            context=context or {"filename": filename}
        )


class PDFProcessingException(FileProcessingException):
    """PDF processing errors."""
    
    def __init__(
        self,
        detail: str,
        filename: Optional[str] = None,
        page_number: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            filename=filename,
            error_code="PDF_PROCESSING_ERROR",
            context=context or {"filename": filename, "page_number": page_number}
        )


class VectorStoreException(ExternalServiceException):
    """Vector store errors."""
    
    def __init__(
        self,
        detail: str,
        operation: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            detail=detail,
            service_name="vector_store",
            error_code="VECTOR_STORE_ERROR",
            context=context or {"operation": operation}
        )


# Rate Limiting Exceptions
class RateLimitException(BaseRAGException):
    """Rate limiting errors."""
    
    def __init__(
        self,
        detail: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        headers = {"Retry-After": str(retry_after)} if retry_after else None
        super().__init__(
            detail=detail,
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers=headers,
            error_code="RATE_LIMIT_EXCEEDED",
            context=context or {"retry_after": retry_after}
        )