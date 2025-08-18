from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Request, Query, Path

from auth.decorators import authorize
from services.document import (
    get_documents_by_tags,
    list_documents,
    get_documents_by_source_filename,
    get_documents_by_compliance_domain,
    get_documents_by_version,
    get_documents_by_domain_and_version
)
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
        
        # Call service
        result = list_documents(
            skip=skip,
            limit=limit,
            compliance_domain=compliance_domain,
            document_version=document_version,
            source_filename=source_filename,
            document_tags=document_tags,
            tags_match_mode=tags_match_mode,
            approval_status=approval_status,
            uploaded_by=uploaded_by,
            approved_by=approved_by
        )
        
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
        
        # Return paginated response if result has pagination info
        if isinstance(result, dict) and "documents" in result:
            return create_paginated_response(
                data=result["documents"],
                total=result.get("total", 0),
                skip=skip,
                limit=limit,
                filters_applied={
                    "compliance_domain": compliance_domain,
                    "document_version": document_version,
                    "tags_match_mode": tags_match_mode
                }
            )
        else:
            return create_success_response(data=result)
        
    except (ValidationException, BusinessLogicException):
        raise
    except Exception as e:
        logger.error(f"Error listing documents: {e}", exc_info=True)
        raise BusinessLogicException(
            detail="Failed to retrieve documents",
            error_code="DOCUMENT_LIST_FAILED",
            context={"filters": {"compliance_domain": compliance_domain}}
        )


@router.get("/by-tags",
    summary="Get documents filtered by specific tags",
    description="Retrieve documents that match specified tags with flexible matching modes",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_documents_by_tags_endpoint(
    request: DocumentTagsRequest,
) -> List[Dict[str, Any]]:
    return get_documents_by_tags(
        tags=request.document_tags,
        match_mode=request.tags_match_mode,
        compliance_domain=request.compliance_domain,
        skip=request.skip,
        limit=request.limit
    )


@router.get("/by-source/{source_filename}",
    summary="Get all chunks from a specific source file",
    description="Fetches all document chunks from a specific source PDF file, ordered by chunk index."
)
@authorize(allowed_roles=["admin"], check_active=True)
async def get_documents_by_source(
    source_filename: str,
    request: Request
) -> Any:
    """Enhanced source file document retrieval."""
    
    try:
        # Validate filename
        if not source_filename or not source_filename.strip():
            raise ValidationException(
                detail="Source filename cannot be empty",
                field="source_filename",
                value=source_filename
            )
        
        # Call service
        result = get_documents_by_source_filename(source_filename.strip())
        
        # Check if documents were found
        if not result:
            raise ResourceNotFoundException(
                resource_type="Documents",
                resource_id=f"source_filename={source_filename}"
            )
        
        # Log business event
        log_business_event(
            event_type="DOCUMENTS_BY_SOURCE_RETRIEVED",
            entity_type="document",
            entity_id="source_file",
            action="read",
            details={"source_filename": source_filename}
        )
        
        return create_success_response(
            data=result,
            meta={"source_filename": source_filename, "count": len(result)}
        )
        
    except (ValidationException, ResourceNotFoundException):
        raise
    except Exception as e:
        logger.error(f"Error retrieving documents by source {source_filename}: {e}", exc_info=True)
        raise BusinessLogicException(
            detail="Failed to retrieve documents by source",
            error_code="DOCUMENT_SOURCE_RETRIEVAL_FAILED",
            context={"source_filename": source_filename}
        )


@router.get("/by-domain/{compliance_domain}",
    summary="Get documents by compliance domain",
    description="Fetches all documents within a specific compliance domain (e.g., GDPR, ISO27001).",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_documents_by_domain(
    compliance_domain: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
) -> Any:
    return get_documents_by_compliance_domain(compliance_domain, skip, limit)


@router.get("/by-version/{document_version}",
    summary="Get documents by version",
    description="Fetches all documents with a specific version identifier.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_documents_by_version(
    document_version: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
) -> Any:
    return get_documents_by_version(document_version, skip, limit)


@router.get("/tags/{tag}/documents",
    summary="Get all documents with a specific tag",
    description="Retrieve all documents that have been tagged with a specific tag",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_documents_with_tag(
    tag: str = Path(..., description="Tag to search for"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
) -> List[Dict[str, Any]]:
    return get_documents_by_tags(
        tags=[tag],
        match_mode="any",
        compliance_domain=compliance_domain,
        skip=skip,
        limit=limit
    )


@router.get("/by-domain-version/{compliance_domain}/{document_version}",
    summary="Get documents by domain and version",
    description="Fetches documents filtered by both compliance domain and version.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_documents_by_domain_version(
    compliance_domain: str,
    document_version: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
) -> Any:
    return get_documents_by_domain_and_version(compliance_domain, document_version, skip, limit)


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