from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Request, Query, Path

from auth.decorators import authorize
from dependencies import DocumentServiceDep
from entities.document import DocumentFilter
from services.schemas import DocumentTagConstants, DocumentTagsRequest

# Enhanced error handling imports
from common.exceptions import (
    ValidationException,
    ResourceNotFoundException,
    BusinessLogicException
)
from common.logging import get_logger, log_business_event, log_performance
from common.validation import validate_pagination_params, validate_compliance_domain
from common.responses import create_success_response, create_paginated_response

router = APIRouter(prefix="/documents", tags=["Documents"])
logger = get_logger("documents")


@router.get("",
    summary="List documents with enhanced filtering including tags",
    description="Fetches paginated documents with comprehensive filtering by tags, compliance domain, version, etc."
)
@authorize(allowed_roles=["admin"], check_active=True)
async def get_all_documents(
    request: Request,
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    document_version: Optional[str] = Query(None, description="Filter by document version"),
    source_filename: Optional[str] = Query(None, description="Filter by source filename (partial match)"),
    document_tags: Optional[List[str]] = Query(None, description="Filter by document tags"),
    tags_match_mode: str = Query("any", description="Tag matching mode: 'any', 'all', or 'exact'"),
    approval_status: Optional[str] = Query(None, description="Filter by approval status"),
    uploaded_by: Optional[str] = Query(None, description="Filter by uploader user ID"),
    approved_by: Optional[str] = Query(None, description="Filter by approver user ID"),
    document_service: DocumentServiceDep = None,
) -> Any:
    """Enhanced document listing with validation and logging."""
    import time
    start_time = time.time()
    
    try:
        # Validate pagination parameters
        skip, limit = validate_pagination_params(skip, limit)
        
        # Validate compliance domain if provided
        if compliance_domain:
            validate_compliance_domain(compliance_domain)
        
        # Validate tags match mode
        if tags_match_mode not in ["any", "all", "exact"]:
            raise ValidationException(
                detail="Invalid tags_match_mode. Must be 'any', 'all', or 'exact'",
                field="tags_match_mode",
                value=tags_match_mode
            )
        
        # Build filters and call service
        filters = DocumentFilter(
            compliance_domain=compliance_domain,
            document_version=document_version,
            source_filename=source_filename,
            document_tags=document_tags,
            tags_match_mode=tags_match_mode,
            approval_status=approval_status,
            uploaded_by=uploaded_by,
            approved_by=approved_by,
        )
        chunks = await document_service.list(skip=skip, limit=limit, filters=filters)
        total = await document_service.count(filters=filters)
        # Convert to dicts and exclude embedding from response
        result = [chunk.model_dump(mode="json", exclude={"embedding"}) for chunk in chunks]
        
        # Log business event
        log_business_event(
            event_type="DOCUMENTS_LISTED",
            entity_type="document",
            entity_id="list",
            action="read",
            details={
                "skip": skip,
                "limit": limit,
                "compliance_domain": compliance_domain,
                "filters_applied": {
                    "document_version": bool(document_version),
                    "source_filename": bool(source_filename),
                    "document_tags": bool(document_tags),
                    "approval_status": bool(approval_status)
                }
            }
        )
        
        # Log performance
        duration_ms = (time.time() - start_time) * 1000
        log_performance(
            operation="list_documents",
            duration_ms=duration_ms,
            success=True,
            item_count=len(result.get("documents", [])) if isinstance(result, dict) else len(result)
        )
        
        return create_paginated_response(
            data=result,
            total=total,
            skip=skip,
            limit=limit,
            filters_applied={
                "compliance_domain": compliance_domain,
                "document_version": document_version,
                "tags_match_mode": tags_match_mode,
            },
        )
        
    except (ValidationException, BusinessLogicException):
        raise
    except Exception as e:
        logger.error(f"Error listing documents: {e}", exc_info=True)
        raise BusinessLogicException(
            detail="Failed to retrieve documents",
            error_code="DOCUMENT_LIST_FAILED",
            context={"filters": {"compliance_domain": compliance_domain}}
        )

@router.get("/tags/constants",
    summary="Get predefined tag constants with descriptions",
    description="Retrieve the predefined tag categories, values, and descriptions for consistent tagging",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer", "reader"], check_active=True)
def get_tag_constants_endpoint() -> Dict[str, Any]:
    return {
        "tag_categories": DocumentTagConstants.get_tags_by_category(),
        "all_tags_with_descriptions": DocumentTagConstants.get_all_tags_with_descriptions(),
        "all_valid_tags": DocumentTagConstants.get_all_valid_tags(),
        "reference_document_tags": DocumentTagConstants.get_reference_document_tags(),
        "implementation_document_tags": DocumentTagConstants.get_implementation_document_tags(),
        "usage_examples": {
            "reference_documents": {
                "tags": ["reference_document", "iso_standard", "current"],
                "description": "Use for ISO standards, regulations, and baseline documents"
            },
            "implementation_documents": {
                "tags": ["implementation_document", "sop", "current"],
                "description": "Use for SOPs, procedures, and internal policies"
            },
            "draft_procedures": {
                "tags": ["implementation_document", "procedure", "draft"],
                "description": "Use for procedures still in development"
            },
            "archived_policies": {
                "tags": ["implementation_document", "internal_policy", "archived"],
                "description": "Use for historical versions of policies"
            }
        }
    }
