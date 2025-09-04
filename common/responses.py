"""
Standardized API response formats for consistent error handling and success responses.
"""

from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone
from uuid import UUID
from pydantic import BaseModel
from fastapi import status
from fastapi.responses import JSONResponse

from common.logging import request_id_var


class ErrorDetail(BaseModel):
    """Detailed error information."""
    code: str
    message: str
    field: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


class APIResponse(BaseModel):
    """Standard API response format."""
    success: bool
    data: Optional[Any] = None
    error: Optional[ErrorDetail] = None
    meta: Optional[Dict[str, Any]] = None
    request_id: Optional[str] = None
    timestamp: str


class PaginatedResponse(BaseModel):
    """Paginated response format."""
    success: bool = True
    data: List[Any]
    meta: Dict[str, Any]
    request_id: Optional[str] = None
    timestamp: str


class ValidationErrorResponse(BaseModel):
    """Validation error response format."""
    success: bool = False
    error: ErrorDetail
    validation_errors: List[Dict[str, Any]]
    request_id: Optional[str] = None
    timestamp: str


def _ensure_jsonable(value: Any) -> Any:
    """Recursively convert common non-JSON-serializable types to JSON-safe values.

    Handles dicts, lists/tuples/sets, datetime, UUID, and Pydantic models.
    Fallback converts unknown objects to str().
    """
    # Primitives
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    # Pydantic models
    if isinstance(value, BaseModel):
        return _ensure_jsonable(value.model_dump(exclude_none=True))

    # Datetime
    if isinstance(value, datetime):
        return value.isoformat()

    # UUID
    if isinstance(value, UUID):
        return str(value)

    # Dict
    if isinstance(value, dict):
        return {k: _ensure_jsonable(v) for k, v in value.items()}

    # List/Tuple
    if isinstance(value, (list, tuple)):
        return [_ensure_jsonable(v) for v in value]

    # Set
    if isinstance(value, set):
        return [_ensure_jsonable(v) for v in value]

    # Fallback to string
    try:
        # If it is already JSON serializable, return as-is
        import json
        json.dumps(value)
        return value
    except Exception:
        return str(value)


def create_success_response(
    data: Any,
    meta: Optional[Dict[str, Any]] = None,
    status_code: int = status.HTTP_200_OK
) -> JSONResponse:
    """Create a successful API response."""
    response_data = APIResponse(
        success=True,
        data=data,
        meta=meta,
        request_id=request_id_var.get(),
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    
    content = _ensure_jsonable(response_data.model_dump(exclude_none=True))
    return JSONResponse(content=content, status_code=status_code)


def create_error_response(
    error_code: str,
    message: str,
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
    field: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None
) -> JSONResponse:
    """Create an error API response."""
    error_detail = ErrorDetail(
        code=error_code,
        message=message,
        field=field,
        context=context
    )
    
    response_data = APIResponse(
        success=False,
        error=error_detail,
        request_id=request_id_var.get(),
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    
    content = _ensure_jsonable(response_data.model_dump(exclude_none=True))
    return JSONResponse(content=content, status_code=status_code)


def create_validation_error_response(
    validation_errors: List[Dict[str, Any]],
    message: str = "Validation failed"
) -> JSONResponse:
    """Create a validation error response."""
    error_detail = ErrorDetail(
        code="VALIDATION_ERROR",
        message=message
    )
    
    response_data = ValidationErrorResponse(
        error=error_detail,
        validation_errors=_ensure_jsonable(validation_errors),
        request_id=request_id_var.get(),
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    
    content = _ensure_jsonable(response_data.model_dump(exclude_none=True))
    return JSONResponse(content=content, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


def create_paginated_response(
    data: List[Any],
    total: Optional[int] = None,
    page: int = 1,
    limit: int = 10,
    skip: int = 0,
    **additional_meta
) -> JSONResponse:
    """Create a paginated response."""
    meta = {
        "pagination": {
            "page": page,
            "limit": limit,
            "skip": skip,
            "total": total,
            "count": len(data)
        },
        **additional_meta
    }
    
    # Calculate additional pagination info if total is provided
    if total is not None:
        meta["pagination"]["total_pages"] = (total + limit - 1) // limit
        meta["pagination"]["has_next"] = skip + limit < total
        meta["pagination"]["has_prev"] = skip > 0
    
    response_data = PaginatedResponse(
        data=data,
        meta=meta,
        request_id=request_id_var.get(),
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    
    content = _ensure_jsonable(response_data.model_dump(exclude_none=True))
    return JSONResponse(content=content, status_code=status.HTTP_200_OK)


def create_not_found_response(
    resource_type: str,
    resource_id: str
) -> JSONResponse:
    """Create a not found response."""
    return create_error_response(
        error_code="RESOURCE_NOT_FOUND",
        message=f"{resource_type} with ID '{resource_id}' not found",
        status_code=status.HTTP_404_NOT_FOUND,
        context={"resource_type": resource_type, "resource_id": resource_id}
    )


def create_unauthorized_response(
    message: str = "Authentication required"
) -> JSONResponse:
    """Create an unauthorized response."""
    return create_error_response(
        error_code="AUTHENTICATION_REQUIRED",
        message=message,
        status_code=status.HTTP_401_UNAUTHORIZED
    )


def create_forbidden_response(
    message: str = "Access denied"
) -> JSONResponse:
    """Create a forbidden response."""
    return create_error_response(
        error_code="ACCESS_DENIED",
        message=message,
        status_code=status.HTTP_403_FORBIDDEN
    )


def create_conflict_response(
    message: str,
    context: Optional[Dict[str, Any]] = None
) -> JSONResponse:
    """Create a conflict response."""
    return create_error_response(
        error_code="RESOURCE_CONFLICT",
        message=message,
        status_code=status.HTTP_409_CONFLICT,
        context=context
    )


def create_rate_limit_response(
    message: str = "Rate limit exceeded",
    retry_after: Optional[int] = None
) -> JSONResponse:
    """Create a rate limit response."""
    headers = {"Retry-After": str(retry_after)} if retry_after else None
    
    response = create_error_response(
        error_code="RATE_LIMIT_EXCEEDED",
        message=message,
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        context={"retry_after": retry_after}
    )
    
    if headers:
        for key, value in headers.items():
            response.headers[key] = value
    
    return response


def create_service_unavailable_response(
    service_name: str,
    message: Optional[str] = None
) -> JSONResponse:
    """Create a service unavailable response."""
    return create_error_response(
        error_code="SERVICE_UNAVAILABLE",
        message=message or f"{service_name} service is temporarily unavailable",
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        context={"service_name": service_name}
    )


# Common response templates
COMMON_RESPONSES = {
    "unauthorized": {
        401: {
            "description": "Authentication required",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": {
                            "code": "AUTHENTICATION_REQUIRED",
                            "message": "Authentication required"
                        },
                        "request_id": "550e8400-e29b-41d4-a716-446655440000",
                        "timestamp": "2023-12-01T10:00:00Z"
                    }
                }
            }
        }
    },
    "forbidden": {
        403: {
            "description": "Access denied",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": {
                            "code": "ACCESS_DENIED",
                            "message": "Access denied"
                        },
                        "request_id": "550e8400-e29b-41d4-a716-446655440000",
                        "timestamp": "2023-12-01T10:00:00Z"
                    }
                }
            }
        }
    },
    "not_found": {
        404: {
            "description": "Resource not found",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": {
                            "code": "RESOURCE_NOT_FOUND",
                            "message": "Resource not found"
                        },
                        "request_id": "550e8400-e29b-41d4-a716-446655440000",
                        "timestamp": "2023-12-01T10:00:00Z"
                    }
                }
            }
        }
    },
    "validation_error": {
        422: {
            "description": "Validation error",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": "Validation failed"
                        },
                        "validation_errors": [
                            {
                                "field": "email",
                                "message": "Invalid email format",
                                "value": "invalid-email"
                            }
                        ],
                        "request_id": "550e8400-e29b-41d4-a716-446655440000",
                        "timestamp": "2023-12-01T10:00:00Z"
                    }
                }
            }
        }
    },
    "rate_limit": {
        429: {
            "description": "Rate limit exceeded",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": {
                            "code": "RATE_LIMIT_EXCEEDED",
                            "message": "Rate limit exceeded"
                        },
                        "request_id": "550e8400-e29b-41d4-a716-446655440000",
                        "timestamp": "2023-12-01T10:00:00Z"
                    }
                }
            }
        }
    },
    "server_error": {
        500: {
            "description": "Internal server error",
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "error": {
                            "code": "INTERNAL_SERVER_ERROR",
                            "message": "An unexpected error occurred"
                        },
                        "request_id": "550e8400-e29b-41d4-a716-446655440000",
                        "timestamp": "2023-12-01T10:00:00Z"
                    }
                }
            }
        }
    }
}
