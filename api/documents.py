from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Query, Path

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

router = APIRouter(prefix="/documents", tags=["Documents"])


@router.get("",
    summary="List documents with enhanced filtering including tags",
    description="Fetches paginated documents with comprehensive filtering by tags, compliance domain, version, etc.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_all_documents(
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
    return list_documents(
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
    description="Fetches all document chunks from a specific source PDF file, ordered by chunk index.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_documents_by_source(
    source_filename: str,
) -> Any:
    return get_documents_by_source_filename(source_filename)


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