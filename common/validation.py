"""
Request validation utilities and decorators.
"""

import uuid
from typing import Any, Dict, List, Optional, Callable
from functools import wraps
from fastapi import HTTPException, status

from common.exceptions import (
    ValidationException,
    InvalidUUIDException,
    BusinessLogicException
)
from common.logging import get_logger

logger = get_logger("validation")

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
    
    def raise_if_errors(self) -> None:
        """Raise validation exception if there are errors."""
        if self.errors:
            from common.responses import create_validation_error_response
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Validation failed"
            )