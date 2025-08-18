"""
Example demonstrating enhanced error handling usage in routers.
This shows how to migrate existing endpoints to use the new error handling system.
"""

from fastapi import APIRouter, Request, HTTPException
from typing import Optional, List, Dict, Any

# Import the enhanced error handling components
from common.exceptions import (
    ValidationException,
    ResourceNotFoundException,
    BusinessLogicException,
    AuthorizationException,
    ExternalServiceException
)
from common.logging import get_logger, log_business_event, log_performance
from common.validation import (
    validate_uuid,
    validate_pagination_params,
    validate_user_access_to_domain,
    RequestValidator
)
from common.responses import (
    create_success_response,
    create_paginated_response,
    create_not_found_response
)

# Example router
router = APIRouter(prefix="/example", tags=["Example"])
logger = get_logger("example")


# BEFORE: Basic endpoint with minimal error handling
@router.get("/basic-old")
def get_items_old(skip: int = 0, limit: int = 10):
    """Old style endpoint - minimal error handling."""
    if skip < 0:
        raise HTTPException(status_code=400, detail="Skip must be non-negative")
    
    # Simulate getting items
    items = [{"id": i, "name": f"Item {i}"} for i in range(skip, skip + limit)]
    return {"items": items, "total": 100}


# AFTER: Enhanced endpoint with comprehensive error handling
@router.get("/basic-enhanced")
async def get_items_enhanced(
    request: Request,
    skip: int = 0,
    limit: int = 10,
    filter_type: Optional[str] = None
):
    """Enhanced endpoint with comprehensive error handling."""
    import time
    start_time = time.time()
    
    try:
        # Validate parameters using common validation
        skip, limit = validate_pagination_params(skip, limit)
        
        # Validate optional parameters
        if filter_type and filter_type not in ["active", "inactive", "all"]:
            raise ValidationException(
                detail="Invalid filter type",
                field="filter_type",
                value=filter_type,
                context={"allowed_values": ["active", "inactive", "all"]}
            )
        
        # Simulate business logic
        items = [{"id": i, "name": f"Item {i}", "type": filter_type or "active"} 
                for i in range(skip, skip + limit)]
        
        # Log business event
        log_business_event(
            event_type="ITEMS_RETRIEVED",
            entity_type="item",
            entity_id="list",
            action="read",
            details={"skip": skip, "limit": limit, "filter": filter_type}
        )
        
        # Calculate performance metrics
        duration_ms = (time.time() - start_time) * 1000
        log_performance(
            operation="get_items",
            duration_ms=duration_ms,
            success=True,
            item_count=len(items)
        )
        
        # Return standardized response
        return create_paginated_response(
            data=items,
            total=100,
            skip=skip,
            limit=limit,
            filter_applied=filter_type
        )
        
    except (ValidationException, BusinessLogicException):
        # Re-raise known exceptions
        raise
    except Exception as e:
        # Handle unexpected errors
        logger.error(f"Unexpected error in get_items_enhanced: {e}", exc_info=True)
        raise ExternalServiceException(
            detail="Failed to retrieve items",
            service_name="item_service",
            context={"operation": "list_items"}
        )


# Example with UUID validation and resource lookup
@router.get("/items/{item_id}")
async def get_item_by_id(item_id: str, request: Request):
    """Enhanced endpoint with UUID validation and resource handling."""
    
    try:
        # Validate UUID format
        validated_id = validate_uuid(item_id, "item_id")
        
        # Simulate item lookup
        if validated_id == "00000000-0000-0000-0000-000000000000":
            raise ResourceNotFoundException(
                resource_type="Item",
                resource_id=validated_id
            )
        
        # Simulate successful retrieval
        item = {
            "id": validated_id,
            "name": f"Item {validated_id[:8]}",
            "status": "active"
        }
        
        log_business_event(
            event_type="ITEM_RETRIEVED",
            entity_type="item",
            entity_id=validated_id,
            action="read"
        )
        
        return create_success_response(
            data=item,
            meta={"retrieved_at": "2023-12-01T10:00:00Z"}
        )
        
    except (ValidationException, ResourceNotFoundException):
        raise
    except Exception as e:
        logger.error(f"Error retrieving item {item_id}: {e}", exc_info=True)
        raise ExternalServiceException(
            detail="Failed to retrieve item",
            service_name="item_service",
            context={"item_id": item_id}
        )


# Example with user access validation
@router.get("/secure-items")
async def get_secure_items(
    compliance_domain: str,
    current_user: Optional[Dict] = None  # Would come from auth decorator
):
    """Enhanced endpoint with user access validation."""
    
    try:
        # Simulate user domains (would come from auth)
        user_domains = ["ISO27001", "GDPR"] if current_user else []
        
        # Validate user access to domain
        validate_user_access_to_domain(user_domains, compliance_domain)
        
        # Simulate getting secure items
        items = [
            {"id": f"secure-{i}", "domain": compliance_domain, "sensitive": True}
            for i in range(5)
        ]
        
        log_business_event(
            event_type="SECURE_ITEMS_ACCESSED",
            entity_type="secure_item",
            entity_id="list",
            action="read",
            user_id=current_user.get("id") if current_user else None,
            details={"compliance_domain": compliance_domain}
        )
        
        return create_success_response(
            data=items,
            meta={
                "compliance_domain": compliance_domain,
                "access_level": "restricted"
            }
        )
        
    except BusinessLogicException:
        raise
    except Exception as e:
        logger.error(f"Error accessing secure items: {e}", exc_info=True)
        raise AuthorizationException(
            detail="Access to secure items failed",
            error_code="SECURE_ACCESS_FAILED"
        )


# Example with complex validation using RequestValidator
@router.post("/complex-item")
async def create_complex_item(item_data: Dict[str, Any], request: Request):
    """Enhanced endpoint with complex validation."""
    
    try:
        # Use RequestValidator for complex validation
        validator = RequestValidator()
        
        # Validate required fields
        validator.validate_required(item_data.get("name"), "name")
        validator.validate_required(item_data.get("category"), "category")
        
        # Validate field formats
        if item_data.get("name"):
            validator.validate_length(item_data["name"], "name", min_length=3, max_length=100)
        
        if item_data.get("priority"):
            validator.validate_range(item_data["priority"], "priority", min_value=1, max_value=10)
        
        if item_data.get("email"):
            validator.validate_email(item_data["email"], "email")
        
        # Raise if any validation errors
        validator.raise_if_errors()
        
        # Simulate item creation
        new_item = {
            "id": "new-item-123",
            "name": item_data["name"],
            "category": item_data["category"],
            "priority": item_data.get("priority", 5),
            "created_at": "2023-12-01T10:00:00Z"
        }
        
        log_business_event(
            event_type="ITEM_CREATED",
            entity_type="item",
            entity_id=new_item["id"],
            action="create",
            details={"category": item_data["category"]}
        )
        
        return create_success_response(
            data=new_item,
            meta={"message": "Item created successfully"},
            status_code=201
        )
        
    except ValidationException:
        raise
    except Exception as e:
        logger.error(f"Error creating item: {e}", exc_info=True)
        raise BusinessLogicException(
            detail="Failed to create item",
            error_code="ITEM_CREATION_FAILED",
            context={"provided_data": list(item_data.keys())}
        )


# Migration guide function
def migration_guide():
    """
    MIGRATION GUIDE: How to enhance existing endpoints
    
    1. Import enhanced error handling components:
       from common.exceptions import ValidationException, ResourceNotFoundException, etc.
       from common.logging import get_logger, log_business_event, log_performance
       from common.validation import validate_uuid, validate_pagination_params, etc.
       from common.responses import create_success_response, create_paginated_response, etc.
    
    2. Replace HTTPException with specific exception types:
       OLD: raise HTTPException(status_code=404, detail="Not found")
       NEW: raise ResourceNotFoundException(resource_type="Item", resource_id=item_id)
    
    3. Add parameter validation:
       OLD: if skip < 0: raise HTTPException(...)
       NEW: skip, limit = validate_pagination_params(skip, limit)
    
    4. Add logging for business events:
       log_business_event(
           event_type="ITEM_RETRIEVED",
           entity_type="item", 
           entity_id=item_id,
           action="read"
       )
    
    5. Use standardized responses:
       OLD: return {"data": items}
       NEW: return create_success_response(data=items)
    
    6. Handle exceptions properly:
       try:
           # business logic
       except (ValidationException, ResourceNotFoundException):
           raise  # Re-raise known exceptions
       except Exception as e:
           logger.error(f"Unexpected error: {e}", exc_info=True)
           raise ExternalServiceException(...)
    
    7. Add performance logging for critical operations:
       start_time = time.time()
       # ... operation ...
       duration_ms = (time.time() - start_time) * 1000
       log_performance("operation_name", duration_ms, success=True)
    """
    pass