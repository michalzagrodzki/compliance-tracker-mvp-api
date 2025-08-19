import logging
import os
from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Body, Query, Path, File, UploadFile, Form, HTTPException

from auth.decorators import ValidatedUser, authorize
from config.config import Settings
from services.audit_log import create_audit_log
from services.ingestion import (
    ingest_pdf_sync,
    list_pdf_ingestions,
    list_pdf_ingestions_by_compliance_domains,
    get_pdf_ingestion_by_id,
    get_pdf_ingestions_by_compliance_domain,
    get_pdf_ingestions_by_user,
    get_pdf_ingestions_by_version,
    search_pdf_ingestions,
    delete_pdf_ingestion,
)
from services.audit_sessions import (
    add_pdf_ingestion_to_session,
    get_pdf_ingestions_for_session,
)
from services.schemas import (
    UploadResponse,
    PdfIngestionSearchRequest,
    PdfIngestionWithRelationship,
    AuditSessionPdfIngestionCreate,
    AuditSessionPdfIngestionBulkCreate,
    AuditSessionPdfIngestionBulkResponse,
    AuditSessionPdfIngestionBulkRemove,
    AuditSessionPdfIngestionBulkRemoveResponse,
    DocumentTagConstants,
)

router = APIRouter(prefix="/ingestions", tags=["Ingestion"])

@router.post("/upload",
    response_model=UploadResponse,
    summary="Upload and ingest PDF document",
    description="Upload a PDF file and automatically ingest it into the vector database with metadata",
    status_code=201
)
@authorize(allowed_roles=["admin"], check_active=True)
def upload_pdf(
    file: UploadFile = File(...),
    compliance_domain: Optional[str] = Form(None, description="Compliance domain (e.g., 'GDPR', 'ISO_27001', 'SOX')"),
    document_version: Optional[str] = Form(None, description="Document version (e.g., 'v1.0', '2024-Q1')"),
    document_tags: Optional[str] = Form(None, description="Comma-separated list of document tags (e.g., 'policy,current,iso_27001')"),
    document_title: Optional[str] = Form(None, description="Document title (overrides PDF metadata)"),
    document_author: Optional[str] = Form(None, description="Document author (overrides PDF metadata)"),
    current_user: ValidatedUser = None
):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported")
    if compliance_domain:
        allowed_domains = ["ISO_27001", "GDPR", "SOX", "HIPAA", "PCI_DSS"]
        if compliance_domain not in allowed_domains:
            logging.warning(f"Unknown compliance domain: {compliance_domain}")

    parsed_tags = []
    if document_tags:
        parsed_tags = [tag.strip() for tag in document_tags.split(",") if tag.strip()]

        valid_tags = DocumentTagConstants.get_all_valid_tags()
        invalid_tags = [tag for tag in parsed_tags if tag not in valid_tags]
        
        if invalid_tags:
            logging.warning(f"Invalid tags provided: {invalid_tags}")
        
    try:
        contents = file.file.read()
        if not contents:
            raise HTTPException(status_code=400, detail="Empty file uploaded")
        
        os.makedirs(Settings.pdf_dir, exist_ok=True)
        safe_filename = os.path.basename(file.filename)
        if not safe_filename:
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        file_path = os.path.join(Settings.pdf_dir, safe_filename)
        
        counter = 1
        original_path = file_path
        while os.path.exists(file_path):
            name, ext = os.path.splitext(original_path)
            file_path = f"{name}_{counter}{ext}"
            counter += 1
        
        with open(file_path, "wb") as f:
            f.write(contents)
        
        logging.info(f"Saved file to {file_path} (size: {len(contents)} bytes)")
        
        chunk_count, ingestion_id = ingest_pdf_sync(
            file_path=file_path,
            compliance_domain=compliance_domain,
            document_version=document_version,
            uploaded_by=current_user.id,
            document_tags=parsed_tags,
            document_author=document_author,
            document_title=document_title
        )
        
        return UploadResponse(
            message=f"PDF '{safe_filename}' ingested successfully",
            inserted_count=chunk_count,
            ingestion_id=ingestion_id,
            compliance_domain=compliance_domain,
            document_version=document_version,
            document_tags=parsed_tags
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Unexpected error during upload: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Upload failed: {str(e)}"
        )
    finally:
        if hasattr(file.file, 'close'):
            file.file.close()

@router.get("",
    summary="List all PDF ingestions",
    description="Get paginated list of all PDF ingestions with optional filtering",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_all_pdf_ingestions(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
) -> List[Dict[str, Any]]:
    return list_pdf_ingestions(skip=skip, limit=limit)

@router.get("/compliance-domains",
    summary="Get PDF ingestions by compliance domains linked to user",
    description="List all PDF ingestions by compliance domains linked to user",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_pdf_ingestions_by_domains(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    current_user: ValidatedUser = None,
) -> List[Dict[str, Any]]:
    user_compliance_domains = getattr(current_user, 'compliance_domains', [])
    
    if not user_compliance_domains:
        raise HTTPException(
            status_code=403, 
            detail="Access denied."
        )

    create_audit_log(
        object_type="document",
        user_id=current_user.id,
        object_id=current_user.id,
        action="view",
        compliance_domain=current_user.compliance_domains[0],
        audit_session_id=None,
        risk_level="high",
        details={},
        ip_address=None,
        user_agent=None
    )

    return list_pdf_ingestions_by_compliance_domains(
        compliance_domains=user_compliance_domains, skip=skip, limit=limit
    )

@router.get("/{ingestion_id}",
    summary="Get PDF ingestion by ID",
    description="Get detailed information about a specific PDF ingestion",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_pdf_ingestion(
    ingestion_id: str = Path(..., description="PDF ingestion UUID"),
) -> Dict[str, Any]:
    return get_pdf_ingestion_by_id(ingestion_id)

@router.get("/compliance-domain/{compliance_domain}",
    summary="Get PDF ingestions by compliance domain",
    description="Get all PDF ingestions for a specific compliance domain",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_pdf_ingestions_by_domain(
    compliance_domain: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    current_user: ValidatedUser = None
) -> List[Dict[str, Any]]:
    user_compliance_domains = getattr(current_user, 'compliance_domains', [])
    
    if compliance_domain not in user_compliance_domains:
        raise HTTPException(
            status_code=403,
            detail="Access denied to this compliance domain."
        )
    
    return get_pdf_ingestions_by_compliance_domain(compliance_domain, skip, limit)

@router.get("/user/{user_id}",
    summary="Get PDF ingestions by user",
    description="Get all PDF ingestions uploaded by a specific user",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_pdf_ingestions_by_user_endpoint(
    user_id: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
) -> List[Dict[str, Any]]:
    return get_pdf_ingestions_by_user(user_id, skip, limit)

@router.get("/version/{document_version}",
    summary="Get PDF ingestions by version",
    description="Get all PDF ingestions for a specific document version",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_pdf_ingestions_by_version_endpoint(
    document_version: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    current_user: ValidatedUser = None
) -> List[Dict[str, Any]]:
    if compliance_domain:
        user_compliance_domains = getattr(current_user, 'compliance_domains', [])
        if compliance_domain not in user_compliance_domains:
            raise HTTPException(
                status_code=403,
                detail="Access denied to this compliance domain."
            )
    
    return get_pdf_ingestions_by_version(
        document_version, skip, limit, compliance_domain
    )

@router.get("/search",
    summary="Search PDF ingestions",
    description="Search PDF ingestions using various criteria",
    response_model=List[PdfIngestionWithRelationship]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def search_pdf_ingestions_endpoint(
    search_request: PdfIngestionSearchRequest,
    current_user: ValidatedUser = None
) -> List[PdfIngestionWithRelationship]:
    # Filter by user's compliance domains
    if search_request.compliance_domain:
        user_compliance_domains = getattr(current_user, 'compliance_domains', [])
        if search_request.compliance_domain not in user_compliance_domains:
            raise HTTPException(
                status_code=403,
                detail="Access denied to this compliance domain."
            )
    
    return search_pdf_ingestions(
        compliance_domain=search_request.compliance_domain,
        uploaded_by=search_request.uploaded_by,
        document_version=search_request.document_version,
        processing_status=search_request.processing_status,
        filename_search=search_request.filename_search,
        ingested_after=search_request.ingested_after,
        ingested_before=search_request.ingested_before,
        document_tags=search_request.document_tags,
        tags_match_mode=search_request.tags_match_mode,
        skip=search_request.skip,
        limit=search_request.limit
    )

@router.delete("/{ingestion_id}",
    summary="Delete PDF ingestion",
    description="Delete a PDF ingestion and its associated documents",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin"], check_active=True)
def delete_pdf_ingestion_endpoint(
    ingestion_id: str,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return delete_pdf_ingestion(ingestion_id, current_user.id)

@router.get("/tags/constants",
    summary="Get predefined tag constants for PDF ingestions",
    description="Retrieve the predefined tag categories, values, and descriptions for consistent PDF ingestion tagging",
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

# Audit Session PDF Ingestion Management
@router.post("/audit-sessions/{session_id}",
    summary="Add PDF ingestion to audit session",
    description="Associate a PDF ingestion with an audit session",
    response_model=Dict[str, Any],
    status_code=201
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def add_pdf_ingestion_to_audit_session(
    session_id: str = Path(..., description="Audit session ID"),
    request_data: AuditSessionPdfIngestionCreate = Body(..., description="PDF ingestion to add"),
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return add_pdf_ingestion_to_session(
        session_id=session_id,
        pdf_ingestion_id=str(request_data.pdf_ingestion_id),
        added_by=str(current_user.id),
        notes=request_data.notes
    )

@router.post("/audit-sessions/{session_id}/pdf-ingestions/bulk",
    summary="Bulk add PDF ingestions to audit session",
    description="Associate multiple PDF ingestions with an audit session",
    response_model=AuditSessionPdfIngestionBulkResponse,
    status_code=201
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def bulk_add_pdf_ingestions_to_audit_session(
    session_id: str = Path(..., description="Audit session ID"),
    request_data: AuditSessionPdfIngestionBulkCreate = Body(..., description="PDF ingestions to add"),
    current_user: ValidatedUser = None
) -> AuditSessionPdfIngestionBulkResponse:
    from services.audit_sessions import bulk_add_pdf_ingestions_to_session
    
    result = bulk_add_pdf_ingestions_to_session(
        session_id=session_id,
        pdf_ingestion_ids=[str(pid) for pid in request_data.pdf_ingestion_ids],
        added_by=str(current_user.id),
        notes=request_data.notes
    )
    
    return AuditSessionPdfIngestionBulkResponse(**result)

@router.get("/audit-sessions/{session_id}",
    summary="Get PDF ingestions for audit session",
    description="Get all PDF ingestions associated with an audit session",
    response_model=List[PdfIngestionWithRelationship]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_session_pdf_ingestions(
    session_id: str = Path(..., description="Audit session ID"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
) -> List[PdfIngestionWithRelationship]:
    results = get_pdf_ingestions_for_session(
        session_id=session_id,
        skip=skip,
        limit=limit
    )
    
    return [PdfIngestionWithRelationship(**item) for item in results]

@router.delete("/audit-sessions/{session_id}/pdf-ingestions/{pdf_ingestion_id}",
    summary="Remove PDF ingestion from audit session",
    description="Remove the association between a PDF ingestion and an audit session",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def remove_pdf_ingestion_from_audit_session(
    session_id: str = Path(..., description="Audit session ID"),
    pdf_ingestion_id: str = Path(..., description="PDF ingestion ID"),
) -> Dict[str, Any]:
    from services.audit_sessions import remove_pdf_ingestion_from_session
    
    return remove_pdf_ingestion_from_session(
        session_id=session_id,
        pdf_ingestion_id=pdf_ingestion_id
    )

@router.delete("/audit-sessions/{session_id}/pdf-ingestions/bulk",
    summary="Bulk remove PDF ingestions from audit session",
    description="Remove multiple PDF ingestion associations from an audit session",
    response_model=AuditSessionPdfIngestionBulkRemoveResponse
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def bulk_remove_pdf_ingestions_from_audit_session(
    session_id: str = Path(..., description="Audit session ID"),
    request_data: AuditSessionPdfIngestionBulkRemove = Body(..., description="PDF ingestions to remove"),
) -> AuditSessionPdfIngestionBulkRemoveResponse:
    from services.audit_sessions import bulk_remove_pdf_ingestions_from_session
    
    result = bulk_remove_pdf_ingestions_from_session(
        session_id=session_id,
        pdf_ingestion_ids=[str(pid) for pid in request_data.pdf_ingestion_ids]
    )
    
    return AuditSessionPdfIngestionBulkRemoveResponse(**result)
