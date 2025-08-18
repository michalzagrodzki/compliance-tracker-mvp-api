"""
Request validation utilities and decorators.
"""

import uuid
from typing import Any, Dict, List, Optional, Callable
from functools import wraps
from fastapi import HTTPException, status
from pydantic import BaseModel, ValidationError

from common.exceptions import (
    ValidationException,
    InvalidUUIDException,
    BusinessLogicException,
    ComplianceDomainMismatchException,
    AuditSessionMismatchException
)
from common.logging import get_logger

logger = get_logger("validation")


def validate_uuid(value: str, field_name: str = "id") -> str:
    """Validate that a string is a valid UUID."""
    try:
        uuid.UUID(value)
        return value
    except (ValueError, TypeError):
        raise InvalidUUIDException(field=field_name, value=value)


def validate_pagination_params(skip: int, limit: int) -> tuple[int, int]:
    """Validate pagination parameters."""
    if skip < 0:
        raise ValidationException(
            detail="Skip parameter must be non-negative",
            field="skip",
            value=skip
        )
    
    if limit <= 0:
        raise ValidationException(
            detail="Limit parameter must be positive",
            field="limit",
            value=limit
        )
    
    if limit > 1000:
        raise ValidationException(
            detail="Limit parameter cannot exceed 1000",
            field="limit",
            value=limit
        )
    
    return skip, limit


def validate_compliance_domain(domain: str, allowed_domains: Optional[List[str]] = None) -> str:
    """Validate compliance domain."""
    if not domain or not domain.strip():
        raise ValidationException(
            detail="Compliance domain cannot be empty",
            field="compliance_domain",
            value=domain
        )
    
    if allowed_domains and domain not in allowed_domains:
        raise ValidationException(
            detail=f"Invalid compliance domain. Allowed: {allowed_domains}",
            field="compliance_domain",
            value=domain,
            context={"allowed_domains": allowed_domains}
        )
    
    return domain.strip()


def validate_file_upload(file, allowed_extensions: List[str], max_size_mb: int = 10) -> None:
    """Validate file upload."""
    if not file.filename:
        raise ValidationException(
            detail="No filename provided",
            field="file"
        )
    
    # Check file extension
    file_ext = file.filename.lower().split('.')[-1]
    if file_ext not in allowed_extensions:
        raise ValidationException(
            detail=f"Invalid file type. Allowed: {allowed_extensions}",
            field="file",
            value=file_ext,
            context={"allowed_extensions": allowed_extensions}
        )
    
    # Check file size if available
    if hasattr(file, 'size') and file.size:
        max_size_bytes = max_size_mb * 1024 * 1024
        if file.size > max_size_bytes:
            raise ValidationException(
                detail=f"File size exceeds {max_size_mb}MB limit",
                field="file",
                value=f"{file.size / (1024*1024):.2f}MB",
                context={"max_size_mb": max_size_mb}
            )


def validate_audit_session_consistency(
    items: List[Dict[str, Any]],
    expected_audit_session_id: str,
    item_type: str = "item"
) -> None:
    """Validate that all items belong to the same audit session."""
    mismatched_items = []
    
    for item in items:
        item_audit_session = item.get('audit_session_id')
        if item_audit_session and str(item_audit_session) != str(expected_audit_session_id):
            mismatched_items.append({
                "item_id": item.get('id'),
                "expected": expected_audit_session_id,
                "actual": item_audit_session
            })
    
    if mismatched_items:
        raise AuditSessionMismatchException(
            expected_session=expected_audit_session_id,
            actual_session="multiple",
            context={
                "mismatched_count": len(mismatched_items),
                "mismatched_items": mismatched_items,
                "item_type": item_type
            }
        )


def validate_compliance_domain_consistency(
    items: List[Dict[str, Any]],
    expected_domain: str,
    item_type: str = "item"
) -> None:
    """Validate that all items belong to the same compliance domain."""
    mismatched_items = []
    
    for item in items:
        item_domain = item.get('compliance_domain')
        if item_domain and item_domain != expected_domain:
            mismatched_items.append({
                "item_id": item.get('id'),
                "expected": expected_domain,
                "actual": item_domain
            })
    
    if mismatched_items:
        raise ComplianceDomainMismatchException(
            expected_domain=expected_domain,
            actual_domain="multiple",
            context={
                "mismatched_count": len(mismatched_items),
                "mismatched_items": mismatched_items,
                "item_type": item_type
            }
        )


def validate_user_access_to_domain(
    user_domains: List[str],
    requested_domain: str
) -> None:
    """Validate that user has access to the requested compliance domain."""
    if requested_domain not in user_domains:
        raise BusinessLogicException(
            detail=f"Access denied to compliance domain '{requested_domain}'",
            error_code="DOMAIN_ACCESS_DENIED",
            context={
                "requested_domain": requested_domain,
                "user_domains": user_domains
            }
        )


def validate_request_body_size(content_length: Optional[str], max_size_mb: int = 10) -> None:
    """Validate request body size."""
    if not content_length:
        return
    
    try:
        size_bytes = int(content_length)
        max_size_bytes = max_size_mb * 1024 * 1024
        
        if size_bytes > max_size_bytes:
            raise ValidationException(
                detail=f"Request body size exceeds {max_size_mb}MB limit",
                field="content_length",
                value=f"{size_bytes / (1024*1024):.2f}MB",
                context={"max_size_mb": max_size_mb}
            )
    except ValueError:
        raise ValidationException(
            detail="Invalid content-length header",
            field="content_length",
            value=content_length
        )


def validate_enum_value(value: str, enum_class, field_name: str) -> Any:
    """Validate that a value is a valid enum member."""
    try:
        return enum_class(value)
    except ValueError:
        valid_values = [e.value for e in enum_class]
        raise ValidationException(
            detail=f"Invalid {field_name}. Valid options: {valid_values}",
            field=field_name,
            value=value,
            context={"valid_values": valid_values}
        )


def validate_date_range(start_date: Optional[str], end_date: Optional[str]) -> None:
    """Validate date range parameters."""
    if not start_date or not end_date:
        return
    
    from datetime import datetime
    
    try:
        start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        
        if start >= end:
            raise ValidationException(
                detail="Start date must be before end date",
                context={
                    "start_date": start_date,
                    "end_date": end_date
                }
            )
    except ValueError as e:
        raise ValidationException(
            detail=f"Invalid date format: {str(e)}",
            context={
                "start_date": start_date,
                "end_date": end_date
            }
        )


class RequestValidator:
    """Class-based request validator for complex validation scenarios."""
    
    def __init__(self):
        self.errors: List[Dict[str, Any]] = []
    
    def add_error(self, field: str, message: str, value: Any = None) -> None:
        """Add a validation error."""
        self.errors.append({
            "field": field,
            "message": message,
            "value": value
        })
    
    def validate_required(self, value: Any, field: str) -> bool:
        """Validate that a field is not empty."""
        if value is None or (isinstance(value, str) and not value.strip()):
            self.add_error(field, "This field is required", value)
            return False
        return True
    
    def validate_uuid_field(self, value: str, field: str) -> bool:
        """Validate UUID field."""
        try:
            uuid.UUID(value)
            return True
        except (ValueError, TypeError):
            self.add_error(field, "Invalid UUID format", value)
            return False
    
    def validate_email(self, value: str, field: str) -> bool:
        """Validate email format."""
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, value):
            self.add_error(field, "Invalid email format", value)
            return False
        return True
    
    def validate_length(self, value: str, field: str, min_length: int = 0, max_length: int = None) -> bool:
        """Validate string length."""
        if len(value) < min_length:
            self.add_error(field, f"Must be at least {min_length} characters", value)
            return False
        
        if max_length and len(value) > max_length:
            self.add_error(field, f"Must be no more than {max_length} characters", value)
            return False
        
        return True
    
    def validate_range(self, value: int, field: str, min_value: int = None, max_value: int = None) -> bool:
        """Validate numeric range."""
        if min_value is not None and value < min_value:
            self.add_error(field, f"Must be at least {min_value}", value)
            return False
        
        if max_value is not None and value > max_value:
            self.add_error(field, f"Must be no more than {max_value}", value)
            return False
        
        return True
    
    def raise_if_errors(self) -> None:
        """Raise validation exception if there are errors."""
        if self.errors:
            from common.responses import create_validation_error_response
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Validation failed"
            )


def validate_request(validator_func: Callable) -> Callable:
    """Decorator for request validation."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                # Run validation
                await validator_func(*args, **kwargs)
                # If validation passes, call the original function
                return await func(*args, **kwargs)
            except ValidationException:
                # Re-raise validation exceptions
                raise
            except Exception as e:
                # Convert unexpected validation errors
                logger.error(f"Validation error in {func.__name__}: {e}", exc_info=True)
                raise ValidationException(
                    detail=f"Validation failed: {str(e)}",
                    context={"function": func.__name__}
                )
        return wrapper
    return decorator