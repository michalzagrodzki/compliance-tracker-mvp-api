import datetime
import os
from pathlib import Path
import uuid
from fastapi import Depends, FastAPI, HTTPException, APIRouter, File, Request, UploadFile, Form, Path, Body, Query
from fastapi.security import HTTPAuthorizationCredentials
from services.authentication import RefreshTokenRequest, TokenResponse, UserLogin, UserSignup
from services.chat_history import get_audit_session_history, get_chat_history, get_domain_history, get_user_history, insert_chat_history
from services.compliance_domain import get_compliance_domain_by_code, list_compliance_domains
from services.compliance_gaps import assign_gap_to_user, create_compliance_gap, get_chat_history_by_id, get_compliance_gap_by_id, get_compliance_gaps_statistics, get_document_by_id, get_gaps_by_audit_session, get_gaps_by_domain, get_gaps_by_user, list_compliance_gaps, log_document_access, mark_gap_reviewed, update_compliance_gap, update_gap_status
from services.db_check import check_database_connection
from services.document import (
    list_documents, 
    get_documents_by_source_filename,
    get_documents_by_compliance_domain, 
    get_documents_by_version,
    get_documents_by_domain_and_version
)
from services.schemas import (
    AuditSessionCreateResponse,
    ComplianceDomain,
    ComplianceGapCreate,
    ComplianceGapFromChatHistoryRequest,
    ComplianceGapStatusUpdate,
    ComplianceGapUpdate,
    QueryRequest, 
    QueryResponse, 
    ChatHistoryItem, 
    UploadResponse,
    AuditSessionCreate, 
    AuditSessionUpdate, 
    AuditSessionResponse,
    AuditSessionSearchRequest
)
from services.history import get_history
from services.ingestion import ingest_pdf_sync
from services.qa import answer_question
from typing import Any, List, Dict, Optional, Union
import logging
from config.config import settings, tags_metadata
from fastapi.responses import StreamingResponse
from services.streaming import stream_answer_sync
from config.cors import configure_cors
from services.audit_sessions import (
    get_audit_session_statistics,
    list_audit_sessions,
    get_audit_sessions_by_user,
    get_audit_session_by_id,
    get_audit_sessions_by_active_status,
    get_audit_sessions_by_domain,
    search_audit_sessions,
    create_audit_session,
    update_audit_session
)
from services.document_access_log import (
    list_document_access_logs,
    get_document_access_log_by_id,
    list_document_access_logs_by_user,
    list_document_access_logs_by_document,
    list_document_access_logs_by_audit_session,
    list_document_access_logs_filtered
)
from services.authentication import (
    auth_service, 
    UserSignup, 
    UserLogin, 
    TokenResponse, 
    RefreshTokenRequest,
    UserResponse,
    get_current_user,
    get_current_active_user,
    require_admin,
    require_compliance_officer_or_admin,
)
from services.schemas import (
    AuditReportCreate,
    AuditReportUpdate, 
    AuditReportResponse,
    AuditReportGenerateRequest,
    AuditReportStatusUpdate,
    AuditReportSearchRequest,
    AuditReportStatisticsResponse,
    AuditReportBulkActionRequest,
    AuditReportVersionCreate,
    AuditReportVersionResponse,
    AuditReportDistributionCreate,
    AuditReportDistributionResponse,
    AuditReportAccessLogRequest
)
from services.audit_reports import (
    list_audit_reports,
    get_audit_report_by_id,
    create_audit_report,
    update_audit_report,
    delete_audit_report,
    generate_audit_report_from_session,
    get_audit_report_statistics
)
from services.audit_report_versions import (
    list_audit_report_versions,
    get_audit_report_version_by_id,
    get_latest_audit_report_version,
    get_audit_report_version_by_number,
    create_audit_report_version,
    compare_audit_report_versions,
    restore_audit_report_version,
    delete_audit_report_version,
    get_version_history_summary
)
from services.audit_report_distributions import (
    list_audit_report_distributions,
    get_audit_report_distribution_by_id,
    get_distributions_by_report_id,
    create_audit_report_distribution,
    log_distribution_access,
    deactivate_distribution,
    reactivate_distribution,
    update_distribution_expiry,
    get_distribution_statistics,
    bulk_distribute_report,
    delete_distribution,
    cleanup_expired_distributions,
    get_distribution_access_summary
)
from datetime import datetime, time, timezone
from services.audit_sessions import ( delete_audit_session, get_audit_session_statistics )
from services.user_management import UserUpdate, activate_user, deactivate_user, get_user_by_id, get_users_by_compliance_domain, get_users_by_role, list_users, update_user

logging.basicConfig(
    level=logging.DEBUG,  # or DEBUG
    format="%(asctime)s - %(levelname)s - %(message)s"
)

app = FastAPI(
    title="RAG FastAPI Supabase API",
    version="1.0.0",
    description="RAG service using Supabase vector store and OpenAI API",
    openapi_tags=tags_metadata,
)

configure_cors(app)

router_v1 = APIRouter(prefix="/v1")

@router_v1.get("/test-db",
               tags=["Health"])
def test_db():
    data = check_database_connection()
    return {"status": "ok", "result": data}

# Authentication endpoints
@router_v1.post("/auth/signup",
    response_model=TokenResponse,
    summary="Register a new user",
    description="Create a new user account with email and password",
    tags=["Authentication"],
    status_code=201
)
def signup(user_data: UserSignup):
    return auth_service.signup(user_data)

@router_v1.post("/auth/login",
    response_model=TokenResponse,
    summary="Login user",
    description="Authenticate user with email and password",
    tags=["Authentication"]
)
def login(login_data: UserLogin):
    return auth_service.login(login_data)

@router_v1.post("/auth/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Get a new access token using refresh token",
    tags=["Authentication"]
)
def refresh_token(refresh_data: RefreshTokenRequest):
    return auth_service.refresh_token(refresh_data)

@router_v1.post("/auth/logout",
    summary="Logout user",
    description="Logout user and invalidate tokens",
    tags=["Authentication"]
)
def logout(credentials: HTTPAuthorizationCredentials = Depends(get_current_user)):
    return auth_service.logout(credentials.credentials)

@router_v1.get("/auth/me",
    response_model=UserResponse,
    summary="Get current user profile",
    description="Get the profile of the currently authenticated user",
    tags=["Authentication"]
)
def get_me(current_user: UserResponse = Depends(get_current_user)):
    return current_user

@router_v1.get("/documents",
    summary="List documents with filtering and pagination",
    description="Fetches paginated rows from the Supabase 'documents' table with optional filtering by compliance domain, version, and source filename.",
    response_model=List[Dict[str, Any]],
    tags=["Documents"],
)
def get_all_documents(
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain (e.g., 'GDPR', 'ISO27001')"),
    document_version: Optional[str] = Query(None, description="Filter by document version (e.g., 'v1.2', '2024-Q1')"),
    source_filename: Optional[str] = Query(None, description="Filter by source filename (exact match or partial)")
) -> Any:
    return list_documents(
        skip=skip, 
        limit=limit, 
        compliance_domain=compliance_domain,
        document_version=document_version,
        source_filename=source_filename
    )

@router_v1.get("/documents/by-source/{source_filename}",
    summary="Get all chunks from a specific source file",
    description="Fetches all document chunks from a specific source PDF file, ordered by chunk index.",
    response_model=List[Dict[str, Any]],
    tags=["Documents"],
)
def get_documents_by_source(source_filename: str) -> Any:
    return get_documents_by_source_filename(source_filename)


@router_v1.get("/documents/by-domain/{compliance_domain}",
    summary="Get documents by compliance domain",
    description="Fetches all documents within a specific compliance domain (e.g., GDPR, ISO27001).",
    response_model=List[Dict[str, Any]],
    tags=["Documents"],
)
def get_documents_by_domain(
    compliance_domain: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return")
) -> Any:
    return get_documents_by_compliance_domain(compliance_domain, skip, limit)


@router_v1.get("/documents/by-version/{document_version}",
    summary="Get documents by version",
    description="Fetches all documents with a specific version identifier.",
    response_model=List[Dict[str, Any]],
    tags=["Documents"],
)
def get_documents_by_version(
    document_version: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return")
) -> Any:
    return get_documents_by_version(document_version, skip, limit)


@router_v1.get("/documents/by-domain-version/{compliance_domain}/{document_version}",
    summary="Get documents by domain and version",
    description="Fetches documents filtered by both compliance domain and version.",
    response_model=List[Dict[str, Any]],
    tags=["Documents"],
)
def get_documents_by_domain_version(
    compliance_domain: str,
    document_version: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return")
) -> Any:
    return get_documents_by_domain_and_version(compliance_domain, document_version, skip, limit)

@router_v1.post("/query",
    response_model=QueryResponse,
    summary="Query the knowledge base with compliance tracking",
    description="Retrieval-Augmented Generation over ingested documents with full audit trail logging.",
    tags=["RAG"],
)
def query_qa(req: QueryRequest, request: Request) -> QueryResponse:
    start_time = time.time()
    
    # Extract client information for audit trail
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    # Validate audit session if provided
    audit_session_data = None
    if req.audit_session_id:
        try:
            audit_session_data = get_audit_session_by_id(req.audit_session_id)
            if not audit_session_data.get("is_active", False):
                raise HTTPException(status_code=400, detail="Audit session is not active")
        except HTTPException as e:
            if e.status_code == 404:
                raise HTTPException(status_code=400, detail="Invalid audit session ID")
            raise

    # Set compliance domain from audit session or request
    compliance_domain = None
    if audit_session_data:
        compliance_domain = audit_session_data.get("compliance_domain")
    elif hasattr(req, 'compliance_domain') and req.compliance_domain:
        compliance_domain = req.compliance_domain

    # Execute the query with domain filtering if specified
    answer, sources = answer_question(
        question=req.question,
        match_threshold=getattr(req, 'match_threshold', 0.75),
        match_count=getattr(req, 'match_count', 5),
        compliance_domain=compliance_domain
    )
    
    end_time = time.time()
    response_time_ms = int((end_time - start_time) * 1000)
    
    # Extract source document IDs for audit trail
    source_document_ids = [source["id"] for source in sources]
    
    # Log chat history with audit context
    conversation_id = req.conversation_id or str(uuid.uuid4())
    
    try:
        insert_chat_history(
            conversation_id=conversation_id,
            question=req.question,
            answer=answer,
            audit_session_id=req.audit_session_id,
            compliance_domain=compliance_domain,
            source_document_ids=source_document_ids,
            match_threshold=getattr(req, 'match_threshold', 0.75),
            match_count=getattr(req, 'match_count', 5),
            user_id=getattr(req, 'user_id', None),
            response_time_ms=response_time_ms,
            total_tokens_used=None
        )
    except Exception as e:
        logging.warning(f"Failed to log chat history: {e}")
    
    # Log document access for audit trail
    if req.audit_session_id and source_document_ids:
        try:
            for doc_id in source_document_ids:
                log_document_access(
                    user_id=getattr(req, 'user_id', None),
                    document_id=doc_id,
                    access_type="reference",
                    audit_session_id=req.audit_session_id,
                    query_text=req.question,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
        except Exception as e:
            logging.warning(f"Failed to log document access: {e}")
    
    # Update audit session query count
    if req.audit_session_id and audit_session_data:
        try:
            current_count = audit_session_data.get("total_queries", 0)
            update_audit_session(
                session_id=req.audit_session_id,
                total_queries=current_count + 1
            )
        except Exception as e:
            logging.warning(f"Failed to update audit session query count: {e}")
    
    return QueryResponse(
        answer=answer, 
        source_docs=sources,
        conversation_id=conversation_id,
        audit_session_id=req.audit_session_id,
        compliance_domain=compliance_domain,
        response_time_ms=response_time_ms
    )

@router_v1.post("/query-stream",
    response_model=None,
    summary="Streamed Q&A with compliance tracking and history",
    description="Streamed responses with full audit trail logging and compliance domain filtering.",
    tags=["RAG"],
)
def query_stream(req: QueryRequest, request: Request):
    start_time = time.time()
    
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    if req.conversation_id:
        try:
            uuid.UUID(req.conversation_id)
            conversation_id = req.conversation_id
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid conversation_id format (must be UUID)")
    else:
        conversation_id = str(uuid.uuid4())

    audit_session_data = None
    if req.audit_session_id:
        try:
            audit_session_data = get_audit_session_by_id(req.audit_session_id)
            if not audit_session_data.get("is_active", False):
                raise HTTPException(status_code=400, detail="Audit session is not active")
        except HTTPException as e:
            if e.status_code == 404:
                raise HTTPException(status_code=400, detail="Invalid audit session ID")
            raise

    compliance_domain = None
    if audit_session_data:
        compliance_domain = audit_session_data.get("compliance_domain")
    elif hasattr(req, 'compliance_domain') and req.compliance_domain:
        compliance_domain = req.compliance_domain

    history = get_history(
        conversation_id=conversation_id,
        audit_session_id=req.audit_session_id,
        compliance_domain=compliance_domain
    )

    def event_generator():
        response_start = time.time()
        source_document_ids = []
        
        for token_data in stream_answer_sync(
            question=req.question,
            conversation_id=conversation_id,
            history=history,
            audit_session_id=req.audit_session_id,
            compliance_domain=compliance_domain,
            match_threshold=getattr(req, 'match_threshold', 0.75),
            match_count=getattr(req, 'match_count', 5),
            user_id=getattr(req, 'user_id', None),
            ip_address=ip_address,
            user_agent=user_agent
        ):
            if isinstance(token_data, dict) and "source_document_ids" in token_data:
                source_document_ids = token_data["source_document_ids"]
                continue
            
            yield token_data
        
        if req.audit_session_id and source_document_ids:
            try:
                for doc_id in source_document_ids:
                    log_document_access(
                        user_id=getattr(req, 'user_id', None),
                        document_id=doc_id,
                        access_type="reference",
                        audit_session_id=req.audit_session_id,
                        query_text=req.question,
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
            except Exception as e:
                logging.warning(f"Failed to log document access: {e}")
        
        # Update audit session query count
        if req.audit_session_id and audit_session_data:
            try:
                current_count = audit_session_data.get("total_queries", 0)
                update_audit_session(
                    session_id=req.audit_session_id,
                    total_queries=current_count + 1
                )
            except Exception as e:
                logging.warning(f"Failed to update audit session query count: {e}")

    return StreamingResponse(
        event_generator(),
        media_type="text/plain; charset=utf-8",
        headers={
            "x-conversation-id": conversation_id,
            "x-audit-session-id": req.audit_session_id or "",
            "x-compliance-domain": compliance_domain or ""
        }
    )

@router_v1.get("/history/{conversation_id}",
    response_model=List[ChatHistoryItem],
    summary="Get chat history for a conversation",
    description="Returns chat history with optional filtering by audit session, domain, or user",
    tags=["History"],
)
def read_history(
    conversation_id: str,
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session UUID"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain code"),
    user_id: Optional[str] = Query(None, description="Filter by user UUID"),
    limit: Optional[int] = Query(None, ge=1, le=1000, description="Limit number of records")
):
    return get_chat_history(
        conversation_id=conversation_id,
        audit_session_id=audit_session_id,
        compliance_domain=compliance_domain,
        user_id=user_id,
        limit=limit
    )

@router_v1.get("/audit-sessions/{audit_session_id}/history",
    response_model=List[ChatHistoryItem],
    summary="Get all chat history for an audit session",
    description="Returns all chat interactions within a specific audit session across conversations",
    tags=["History", "Audit"],
)
def read_audit_session_history(
    audit_session_id: str,
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain")
):
    return get_audit_session_history(
        audit_session_id=audit_session_id,
        compliance_domain=compliance_domain
    )

@router_v1.get("/compliance-domains/{domain_code}/history",
    response_model=List[ChatHistoryItem],
    summary="Get chat history by compliance domain",
    description="Returns all chat history for a specific compliance domain (e.g., GDPR, ISO27001)",
    tags=["History", "Compliance"],
)
def read_domain_history(
    domain_code: str,
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session"),
    user_id: Optional[str] = Query(None, description="Filter by user"),
    limit: Optional[int] = Query(100, ge=1, le=1000, description="Limit number of records"),
    skip: Optional[int] = Query(0, ge=0, description="Skip number of records for pagination")
):
    return get_domain_history(
        domain_code=domain_code,
        audit_session_id=audit_session_id,
        user_id=user_id,
        limit=limit,
        skip=skip
    )

@router_v1.get("/users/{user_id}/history",
    response_model=List[ChatHistoryItem],
    summary="Get chat history by user",
    description="Returns all chat history for a specific user with optional domain filtering",
    tags=["History", "Users"],
)
def read_user_history(
    user_id: str,
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session"),
    limit: Optional[int] = Query(100, ge=1, le=1000, description="Limit number of records"),
    skip: Optional[int] = Query(0, ge=0, description="Skip number of records for pagination")
):
    return get_user_history(
        user_id=user_id,
        compliance_domain=compliance_domain,
        audit_session_id=audit_session_id,
        limit=limit,
        skip=skip
    )

@router_v1.post("/upload",
    response_model=UploadResponse,
    summary="Upload a PDF document with compliance metadata",
    description="Ingests a PDF, splits into chunks, stores embeddings in Supabase with compliance domain tracking",
    tags=["Ingestion"],
)
def upload_pdf(
    file: UploadFile = File(...),
    compliance_domain: Optional[str] = Form(None, description="Compliance domain (e.g., 'GDPR', 'ISO_27001', 'SOX')"),
    document_version: Optional[str] = Form(None, description="Document version (e.g., 'v1.0', '2024-Q1')"),
    uploaded_by: Optional[str] = Form(None, description="User ID who uploaded the document")
):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported")

    if compliance_domain:
        allowed_domains = ["ISO_27001"]
        if compliance_domain not in allowed_domains:
            logging.warning(f"Unknown compliance domain: {compliance_domain}")

    if uploaded_by:
        try:
            uuid.UUID(uploaded_by)
        except ValueError:
            raise HTTPException(status_code=400, detail="uploaded_by must be a valid UUID")
        
    try:
        contents = file.file.read()
        if not contents:
            raise HTTPException(status_code=400, detail="Empty file uploaded")
        
        os.makedirs(settings.pdf_dir, exist_ok=True)
        safe_filename = os.path.basename(file.filename)
        if not safe_filename:
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        file_path = os.path.join(settings.pdf_dir, safe_filename)
        
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
            uploaded_by=uploaded_by
        )
        
        return UploadResponse(
            message=f"PDF '{safe_filename}' ingested successfully",
            inserted_count=chunk_count,
            ingestion_id=ingestion_id,
            compliance_domain=compliance_domain,
            document_version=document_version
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
        # Clean up file handle
        if hasattr(file.file, 'close'):
            file.file.close()

@router_v1.get("/compliance-domains",
    summary="List compliance domains with pagination",
    description="Fetches paginated rows from the Supabase 'compliance_domains' table.",
    response_model=List[ComplianceDomain],
    tags=["Compliance"],
)
def get_compliance_domains(
    skip: Optional[int] = Query(0, ge=0, description="Number of domains to skip for pagination"),
    limit: Optional[int] = Query(10, ge=1, le=100, description="Maximum number of domains to return"),
    is_active: Optional[bool] = Query(None, description="Filter by active status. If None, returns all domains")
) -> List[ComplianceDomain]:
    return list_compliance_domains(skip=skip or 0, limit=limit or 10, is_active=is_active)

@router_v1.get("/compliance-domains/{code}",
    summary="Get compliance domain by code",
    description="Fetches a specific compliance domain by its unique code.",
    response_model=ComplianceDomain,
    tags=["Compliance"],
)
def get_compliance_domain(code: str) -> ComplianceDomain:
    return get_compliance_domain_by_code(code)

@router_v1.get("/audit-sessions",
    summary="List all audit sessions with pagination",
    description="Fetches paginated audit sessions from the Supabase 'audit_sessions' table.",
    response_model=List[AuditSessionResponse],
    tags=["Audit Sessions"],
)
def get_all_audit_sessions(
    skip: int = Query(0, ge=0, description="Number of records to skip"), 
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return")
) -> List[AuditSessionResponse]:
    """Get all audit sessions with pagination."""
    return list_audit_sessions(skip=skip, limit=limit)

@router_v1.get("/audit-sessions/user/{user_id}",
    summary="Get audit sessions by user ID",
    description="Fetches audit sessions for a specific user with pagination.",
    response_model=List[AuditSessionResponse],
    tags=["Audit Sessions"],
)
def get_user_audit_sessions(
    user_id: str = Path(..., description="User ID to filter sessions"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return")
) -> List[AuditSessionResponse]:
    """Get audit sessions for a specific user."""
    return get_audit_sessions_by_user(user_id=user_id, skip=skip, limit=limit)

@router_v1.get("/audit-sessions/{session_id}",
    summary="Get audit session by ID",
    description="Fetches a single audit session by its ID.",
    response_model=AuditSessionResponse,
    tags=["Audit Sessions"],
)
def get_audit_session(
    session_id: str = Path(..., description="Audit session ID")
) -> AuditSessionResponse:
    """Get a single audit session by ID."""
    return get_audit_session_by_id(session_id=session_id)

@router_v1.get("/audit-sessions/status/{is_active}",
    summary="Get audit sessions by active status",
    description="Fetches audit sessions filtered by active/inactive status.",
    response_model=List[AuditSessionResponse],
    tags=["Audit Sessions"],
)
def get_audit_sessions_by_status(
    is_active: bool = Path(..., description="Active status filter (true/false)"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return")
) -> List[AuditSessionResponse]:
    """Get audit sessions by active status."""
    return get_audit_sessions_by_active_status(
        is_active=is_active, skip=skip, limit=limit
    )

@router_v1.get("/audit-sessions/domain/{compliance_domain}",
    summary="Get audit sessions by compliance domain",
    description="Fetches audit sessions for a specific compliance domain.",
    response_model=List[AuditSessionResponse],
    tags=["Audit Sessions"],
)
def get_audit_sessions_by_compliance_domain(
    compliance_domain: str = Path(..., description="Compliance domain (e.g. ISO27001)"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return")
) -> List[AuditSessionResponse]:
    return get_audit_sessions_by_domain(
        compliance_domain=compliance_domain, skip=skip, limit=limit
    )

@router_v1.post("/audit-sessions/search",
    summary="Search audit sessions with multiple filters",
    description="Advanced search for audit sessions with optional filters for domain, user, dates, and status.",
    response_model=List[AuditSessionResponse],
    tags=["Audit Sessions"],
)
def search_audit_sessions_endpoint(
    search_request: AuditSessionSearchRequest
) -> List[AuditSessionResponse]:
    return search_audit_sessions(
        compliance_domain=search_request.compliance_domain,
        user_id=search_request.user_id,
        started_at=search_request.started_at,
        ended_at=search_request.ended_at,
        is_active=search_request.is_active,
        skip=search_request.skip,
        limit=search_request.limit
    )

@router_v1.post("/audit-sessions",
    summary="Create a new audit session",
    description="Creates a new audit session for compliance tracking. Returns the created session with generated ID and timestamps.",
    response_model=AuditSessionResponse,
    tags=["Audit Sessions"],
    status_code=201
)
def create_new_audit_session(
    request: Request,
    session_data: AuditSessionCreate = Body(..., description="Audit session data"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> AuditSessionCreateResponse:
    ip_address = session_data.ip_address or request.client.host if request.client else None
    user_agent = session_data.user_agent or request.headers.get("user-agent")
    user_id = current_user.id
    
    created_session = create_audit_session(
        user_id=user_id,
        session_name=session_data.session_name,
        compliance_domain=session_data.compliance_domain,
        ip_address=ip_address,
        user_agent=user_agent
    )
    return AuditSessionCreateResponse(id = created_session.id)

@router_v1.patch("/audit-sessions/{session_id}",
    summary="Update an audit session",
    description="Updates an existing audit session with new information. Only provided fields will be updated.",
    response_model=AuditSessionResponse,
    tags=["Audit Sessions"],
)
def update_existing_audit_session(
    session_id: str = Path(..., description="Audit session ID to update"),
    update_data: AuditSessionUpdate = Body(..., description="Fields to update")
) -> AuditSessionResponse:
    return update_audit_session(
        session_id=session_id,
        ended_at=update_data.ended_at,
        session_summary=update_data.session_summary,
        is_active=update_data.is_active,
        total_queries=update_data.total_queries
    )

@router_v1.put("/audit-sessions/{session_id}/close",
    summary="Close an audit session",
    description="Convenience endpoint to close an active audit session with optional summary.",
    response_model=AuditSessionResponse,
    tags=["Audit Sessions"],
)
def close_audit_session(
    session_id: str = Path(..., description="Audit session ID to close"),
    session_summary: Optional[str] = Body(None, description="Optional summary of the session", embed=True)
) -> AuditSessionResponse:
    return update_audit_session(
        session_id=session_id,
        ended_at=datetime.now(timezone.utc),
        session_summary=session_summary,
        is_active=False
    )

@router_v1.put("/audit-sessions/{session_id}/activate",
    summary="Reactivate an audit session",
    description="Reactivate a closed audit session for continued use.",
    response_model=AuditSessionResponse,
    tags=["Audit Sessions"],
)
def activate_audit_session(
    session_id: str = Path(..., description="Audit session ID to reactivate")
) -> AuditSessionResponse:
    return update_audit_session(
        session_id=session_id,
        ended_at=None,
        is_active=True
    )

@router_v1.delete("/audit-sessions/{session_id}",
    summary="Delete an audit session",
    description="Soft delete an audit session (sets is_active=False). For compliance, sessions are typically not hard deleted.",
    response_model=AuditSessionResponse,
    tags=["Audit Sessions"],
)
def delete_audit_session_endpoint(
    session_id: str = Path(..., description="Audit session ID to delete"),
    hard_delete: bool = Query(False, description="If true, permanently delete the session (not recommended for compliance)")
) -> Dict[str, Any]:
    
    
    return delete_audit_session(
        session_id=session_id,
        soft_delete=not hard_delete
    )

@router_v1.get("/audit-sessions/statistics",
    summary="Get audit session statistics",
    description="Get comprehensive statistics about audit sessions for reporting and analytics.",
    response_model=Dict[str, Any],
    tags=["Audit Sessions"],
)
def get_audit_session_statistics_endpoint(
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    start_date: Optional[datetime] = Query(None, description="Filter sessions started after this date"),
    end_date: Optional[datetime] = Query(None, description="Filter sessions started before this date")
) -> Dict[str, Any]:
    return get_audit_session_statistics(
        compliance_domain=compliance_domain,
        user_id=user_id,
        start_date=start_date,
        end_date=end_date
    )

@router_v1.get("/document-access-logs",
    summary="List all document access logs with pagination",
    description="Fetches paginated rows from the Supabase 'document_access_log' table.",
    response_model=List[Dict[str, Any]],
    tags=["Audit"],
)
def get_all_document_access_logs(
    skip: int = Query(0, ge=0), 
    limit: int = Query(10, ge=1, le=100)
) -> Any:
    return list_document_access_logs(skip=skip, limit=limit)

@router_v1.get("/document-access-logs/{log_id}",
    summary="Get document access log by ID",
    description="Fetches a specific document access log entry by its ID.",
    response_model=Dict[str, Any],
    tags=["Audit"],
)
def get_document_access_log(log_id: str) -> Any:
    return get_document_access_log_by_id(log_id)

@router_v1.get("/document-access-logs/user/{user_id}",
    summary="List document access logs by user ID",
    description="Fetches paginated document access logs for a specific user.",
    response_model=List[Dict[str, Any]],
    tags=["Audit"],
)
def get_document_access_logs_by_user(
    user_id: str,
    skip: int = Query(0, ge=0), 
    limit: int = Query(10, ge=1, le=100)
) -> Any:
    return list_document_access_logs_by_user(user_id, skip=skip, limit=limit)

@router_v1.get("/document-access-logs/document/{document_id}",
    summary="List document access logs by document ID",
    description="Fetches paginated document access logs for a specific document.",
    response_model=List[Dict[str, Any]],
    tags=["Audit"],
)
def get_document_access_logs_by_document(
    document_id: str,
    skip: int = Query(0, ge=0), 
    limit: int = Query(10, ge=1, le=100)
) -> Any:
    return list_document_access_logs_by_document(document_id, skip=skip, limit=limit)

@router_v1.get("/document-access-logs/audit-session/{audit_session_id}",
    summary="List document access logs by audit session ID",
    description="Fetches paginated document access logs for a specific audit session.",
    response_model=List[Dict[str, Any]],
    tags=["Audit"],
)
def get_document_access_logs_by_audit_session(
    audit_session_id: str,
    skip: int = Query(0, ge=0), 
    limit: int = Query(10, ge=1, le=100)
) -> Any:
    return list_document_access_logs_by_audit_session(audit_session_id, skip=skip, limit=limit)

@router_v1.get("/document-access-logs/filter",
    summary="List document access logs with multiple filters",
    description="Fetches paginated document access logs filtered by user_id, document_id, access_type, and/or audit_session_id.",
    response_model=List[Dict[str, Any]],
    tags=["Audit"],
)
def get_filtered_document_access_logs(
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    document_id: Optional[str] = Query(None, description="Filter by document ID"),
    access_type: Optional[str] = Query(None, description="Filter by access type (view, search, download, reference)"),
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session ID"),
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100)
) -> Any:
    return list_document_access_logs_filtered(
        user_id=user_id,
        document_id=document_id,
        access_type=access_type,
        audit_session_id=audit_session_id,
        skip=skip,
        limit=limit
    )

# User management endpoints (Admin only)
@router_v1.get("/users",
    summary="List all users",
    description="Get paginated list of users (Admin only)",
    response_model=List[Dict[str, Any]],
    tags=["Users"]
)
def get_all_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    role: Optional[str] = Query(None, description="Filter by role"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    current_user: UserResponse = Depends(require_admin)
):
    return list_users(skip=skip, limit=limit, role=role, is_active=is_active)

@router_v1.get("/users/{user_id}",
    summary="Get user by ID",
    description="Get specific user details (Admin only)",
    response_model=Dict[str, Any],
    tags=["Users"]
)
def get_user(
    user_id: str,
    current_user: UserResponse = Depends(require_admin)
):
    return get_user_by_id(user_id)

@router_v1.patch("/users/{user_id}",
    summary="Update user",
    description="Update user profile (Admin only)",
    response_model=Dict[str, Any],
    tags=["Users"]
)
def update_user_profile(
    user_id: str,
    user_update: UserUpdate,
    current_user: UserResponse = Depends(require_admin)
):
    return update_user(user_id, user_update, current_user.id)

@router_v1.put("/users/{user_id}/deactivate",
    summary="Deactivate user",
    description="Deactivate user account (Admin only)",
    response_model=Dict[str, Any],
    tags=["Users"]
)
def deactivate_user_account(
    user_id: str,
    current_user: UserResponse = Depends(require_admin)
):
    return deactivate_user(user_id, current_user.id)

@router_v1.put("/users/{user_id}/activate",
    summary="Activate user",
    description="Activate user account (Admin only)",
    response_model=Dict[str, Any],
    tags=["Users"]
)
def activate_user_account(
    user_id: str,
    current_user: UserResponse = Depends(require_admin)
):
    return activate_user(user_id, current_user.id)

@router_v1.get("/users/role/{role}",
    summary="Get users by role",
    description="Get users with specific role (Admin only)",
    response_model=List[Dict[str, Any]],
    tags=["Users"]
)
def get_users_by_role_endpoint(
    role: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: UserResponse = Depends(require_admin)
):
    return get_users_by_role(role, skip, limit)

@router_v1.get("/users/domain/{domain}",
    summary="Get users by compliance domain",
    description="Get users with access to specific compliance domain (Admin only)",
    response_model=List[Dict[str, Any]],
    tags=["Users"]
)
def get_users_by_domain_endpoint(
    domain: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: UserResponse = Depends(require_admin)
):
    return get_users_by_compliance_domain(domain, skip, limit)

@router_v1.get("/compliance-gaps",
    summary="List compliance gaps with filtering",
    description="Get paginated compliance gaps with optional filtering by domain, type, risk level, etc.",
    response_model=List[Dict[str, Any]],
    tags=["Compliance Gaps"],
    )
def get_all_compliance_gaps(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    gap_type: Optional[str] = Query(None, description="Filter by gap type"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    status: Optional[str] = Query(None, description="Filter by status"),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned user"),
    user_id: Optional[str] = Query(None, description="Filter by creator user"),
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session"),
    detection_method: Optional[str] = Query(None, description="Filter by detection method"),
    regulatory_requirement: Optional[bool] = Query(None, description="Filter by regulatory requirement status"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> List[Dict[str, Any]]:
    return list_compliance_gaps(
        skip=skip,
        limit=limit,
        compliance_domain=compliance_domain,
        gap_type=gap_type,
        risk_level=risk_level,
        status=status,
        assigned_to=assigned_to,
        user_id=user_id,
        audit_session_id=audit_session_id,
        detection_method=detection_method,
        regulatory_requirement=regulatory_requirement
    )

@router_v1.get("/compliance-gaps/{gap_id}",
    summary="Get compliance gap by ID",
    description="Get detailed information about a specific compliance gap",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"],
)
def get_compliance_gap(
    gap_id: str = Path(..., description="Compliance gap UUID"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return get_compliance_gap_by_id(gap_id)

@router_v1.post("/compliance-gaps",
    summary="Create new compliance gap",
    description="Create a new compliance gap record from manual input or existing chat history",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"],
    status_code=201
)
def create_new_compliance_gap(
    request: Union[ComplianceGapCreate, ComplianceGapFromChatHistoryRequest] = Body(
        ..., 
        discriminator="creation_method",
        description="Either a complete gap definition or a reference to chat history"
    ),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    """
    Create a new compliance gap either by providing full details or by referencing an existing chat history item.
    
    There are two ways to create a gap:
    1. Provide a complete ComplianceGapCreate object with all required details
    2. Provide a ComplianceGapFromChatHistoryRequest with chat_history_id and additional metadata
    
    The creation_method field in the request body determines which approach is used.
    """
    try:
        # Check the creation method
        if request.creation_method == "from_chat_history":
            logging.info(f"Creating compliance gap from chat history ID: {request.chat_history_id}")
            
            chat_history = get_chat_history_by_id(request.chat_history_id)
            if not chat_history:
                raise HTTPException(
                    status_code=404,
                    detail=f"Chat history with ID {request.chat_history_id} not found"
                )
            
            search_results = []
            if chat_history.get("source_document_ids"):
                for doc_id in chat_history.get("source_document_ids", []):
                    try:
                        doc = get_document_by_id(doc_id)
                        if doc:
                            search_results.append({
                                "id": doc_id,
                                "content": doc.get("content", ""),
                                "metadata": doc.get("metadata", {}),
                                "similarity": doc.get("similarity", 0.0)
                            })
                    except Exception as e:
                        logging.warning(f"Failed to fetch document {doc_id}: {e}")
            
            gap_data = {
                "user_id": current_user.id,
                "chat_history_id": request.chat_history_id,
                "audit_session_id": chat_history.get("audit_session_id") or request.audit_session_id,
                "compliance_domain": chat_history.get("compliance_domain") or request.compliance_domain,
                "gap_type": request.gap_type,
                "gap_category": request.gap_category,
                "gap_title": request.gap_title,
                "gap_description": request.gap_description,
                "original_question": chat_history.get("question", ""),
                "search_terms_used": request.search_terms_used,
                "similarity_threshold_used": chat_history.get("match_threshold"),
                "best_match_score": max([r.get("similarity", 0) for r in search_results], default=0) if search_results else None,
                "risk_level": request.risk_level,
                "business_impact": request.business_impact,
                "regulatory_requirement": request.regulatory_requirement,
                "potential_fine_amount": request.potential_fine_amount,
                "recommendation_type": request.recommendation_type,
                "recommendation_text": request.recommendation_text,
                "recommended_actions": request.recommended_actions,
                "related_documents": request.related_documents or chat_history.get("source_document_ids", []),
                "detection_method": "manual_review",  # Since this is created manually from chat history
                "confidence_score": request.confidence_score,
                "false_positive_likelihood": request.false_positive_likelihood,
                "auto_generated": False,
                "detected_at": datetime.now(timezone.utc),
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }
        elif request.creation_method == "direct":
            logging.info(f"Creating compliance gap with title: {request.gap_title}")
            
            gap_data = request.dict(exclude={"creation_method"})
            
            if "user_id" not in gap_data or not gap_data["user_id"]:
                gap_data["user_id"] = current_user.id

            gap_data["detected_at"] = datetime.now(timezone.utc)
            gap_data["created_at"] = datetime.now(timezone.utc)
            gap_data["updated_at"] = datetime.now(timezone.utc)
            gap_data["auto_generated"] = False
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid creation_method: {request.creation_method}"
            )
        
        created_gap = create_compliance_gap(gap_data)
        
        if created_gap and current_user and "related_documents" in gap_data and gap_data["related_documents"]:
            try:
                for doc_id in gap_data["related_documents"]:
                    log_document_access(
                        user_id=current_user.id,
                        document_id=doc_id,
                        access_type="reference",
                        audit_session_id=gap_data.get("audit_session_id"),
                        query_text=gap_data.get("original_question")
                    )
            except Exception as e:
                logging.warning(f"Failed to log document access: {e}")
        
        return created_gap
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error creating compliance gap: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create compliance gap: {str(e)}"
        )

@router_v1.patch("/compliance-gaps/{gap_id}",
    summary="Update compliance gap",
    description="Update details of an existing compliance gap",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"],
)
def update_existing_compliance_gap(
    gap_id: str = Path(..., description="Compliance gap UUID"),
    update_data: ComplianceGapUpdate = Body(..., description="Fields to update"),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    update_dict = update_data.model_dump(exclude_unset=True)
    update_dict["updated_at"] = datetime.now(timezone.utc)
    
    return update_compliance_gap(gap_id, update_dict)

@router_v1.put("/compliance-gaps/{gap_id}/status",
    summary="Update compliance gap status",
    description="Change the status of a compliance gap (e.g., to 'acknowledged', 'in_progress', 'resolved')",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"],
)
def update_compliance_gap_status(
    gap_id: str = Path(..., description="Compliance gap UUID"),
    status_update: ComplianceGapStatusUpdate = Body(..., description="New status data"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return update_gap_status(gap_id, status_update.status, status_update.resolution_notes)

@router_v1.put("/compliance-gaps/{gap_id}/assign",
    summary="Assign compliance gap",
    description="Assign a compliance gap to a specific user for resolution",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"],
)
def assign_compliance_gap(
    gap_id: str = Path(..., description="Compliance gap UUID"),
    assigned_to: str = Body(..., description="User ID to assign to", embed=True),
    due_date: Optional[datetime] = Body(None, description="Due date for resolution", embed=True),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    return assign_gap_to_user(gap_id, assigned_to, due_date)

@router_v1.put("/compliance-gaps/{gap_id}/review",
    summary="Mark compliance gap as reviewed",
    description="Mark a compliance gap as reviewed with optional notes",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"],
)
def review_compliance_gap(
    gap_id: str = Path(..., description="Compliance gap UUID"),
    reviewer_notes: Optional[str] = Body(None, description="Notes from the review", embed=True),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    return mark_gap_reviewed(gap_id, reviewer_notes)

@router_v1.get("/compliance-domains/{domain_code}/gaps",
    summary="Get compliance gaps by domain",
    description="Get all compliance gaps for a specific compliance domain",
    response_model=List[Dict[str, Any]],
    tags=["Compliance Gaps"],
)
def get_domain_compliance_gaps(
    domain_code: str = Path(..., description="Compliance domain code"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    status_filter: Optional[str] = Query(None, description="Filter by status"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> List[Dict[str, Any]]:
    return get_gaps_by_domain(domain_code, skip, limit, status_filter)

@router_v1.get("/users/{user_id}/gaps",
    summary="Get compliance gaps by user",
    description="Get compliance gaps created by or assigned to a specific user",
    response_model=List[Dict[str, Any]],
    tags=["Compliance Gaps"],
)
def get_user_compliance_gaps(
    user_id: str = Path(..., description="User UUID"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    assigned_only: bool = Query(False, description="If true, only show gaps assigned to this user"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> List[Dict[str, Any]]:
    return get_gaps_by_user(user_id, skip, limit, assigned_only)

@router_v1.get("/audit-sessions/{audit_session_id}/gaps",
    summary="Get compliance gaps by audit session",
    description="Get all compliance gaps identified during a specific audit session",
    response_model=List[Dict[str, Any]],
    tags=["Compliance Gaps"],
)
def get_audit_session_compliance_gaps(
    audit_session_id: str = Path(..., description="Audit session UUID"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> List[Dict[str, Any]]:
    return get_gaps_by_audit_session(audit_session_id)

@router_v1.get("/compliance-gaps/statistics",
    summary="Get compliance gaps statistics",
    description="Get statistical summaries of compliance gaps",
    response_model=Dict[str, Any],
    tags=["Compliance Gaps"],
)
def get_compliance_gap_statistics(
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    start_date: Optional[datetime] = Query(None, description="Filter gaps detected after this date"),
    end_date: Optional[datetime] = Query(None, description="Filter gaps detected before this date"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return get_compliance_gaps_statistics(
        compliance_domain=compliance_domain,
        user_id=user_id,
        start_date=start_date,
        end_date=end_date
    )

@router_v1.get("/audit-reports",
    summary="List audit reports with filtering",
    description="Get paginated audit reports with optional filtering by domain, type, status, etc.",
    response_model=List[Dict[str, Any]],
    tags=["Audit Reports"],
)
def get_all_audit_reports(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    report_type: Optional[str] = Query(None, description="Filter by report type"),
    report_status: Optional[str] = Query(None, description="Filter by report status"),
    user_id: Optional[str] = Query(None, description="Filter by creator user"),
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session"),
    target_audience: Optional[str] = Query(None, description="Filter by target audience"),
    confidentiality_level: Optional[str] = Query(None, description="Filter by confidentiality level"),
    generated_after: Optional[datetime] = Query(None, description="Filter by generation date (after)"),
    generated_before: Optional[datetime] = Query(None, description="Filter by generation date (before)"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> List[Dict[str, Any]]:
    return list_audit_reports(
        skip=skip,
        limit=limit,
        compliance_domain=compliance_domain,
        report_type=report_type,
        report_status=report_status,
        user_id=user_id,
        audit_session_id=audit_session_id,
        target_audience=target_audience,
        confidentiality_level=confidentiality_level,
        generated_after=generated_after,
        generated_before=generated_before
    )

@router_v1.get("/audit-reports/{report_id}",
    summary="Get audit report by ID",
    description="Get detailed information about a specific audit report",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def get_audit_report(
    report_id: str = Path(..., description="Audit report UUID"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return get_audit_report_by_id(report_id)

@router_v1.post("/audit-reports",
    summary="Create new audit report",
    description="Create a new audit report manually",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
    status_code=201
)
def create_new_audit_report(
    report_data: AuditReportCreate = Body(..., description="Audit report data"),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    report_dict = report_data.model_dump()

    if current_user.role != "admin" and str(report_dict.get("user_id")) != str(current_user.id):
        report_dict["user_id"] = current_user.id
    
    created_report = create_audit_report(report_dict)

    create_audit_report_version(
        audit_report_id=created_report["id"],
        changed_by=str(current_user.id),
        change_description="Initial report creation",
        change_type="draft_update",
        report_snapshot=created_report
    )
    
    return created_report

@router_v1.post("/audit-reports/generate",
    summary="Generate audit report from session",
    description="Generate a comprehensive audit report from an existing audit session",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
    status_code=201
)
def generate_audit_report(
    generate_request: AuditReportGenerateRequest = Body(..., description="Report generation parameters"),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    generation_options = {
        "include_technical_details": generate_request.include_technical_details,
        "include_source_citations": generate_request.include_source_citations,
        "include_confidence_scores": generate_request.include_confidence_scores,
        "target_audience": generate_request.target_audience,
        "confidentiality_level": generate_request.confidentiality_level
    }
    
    report = generate_audit_report_from_session(
        audit_session_id=str(generate_request.audit_session_id),
        user_id=str(current_user.id),
        report_title=generate_request.report_title,
        report_type=generate_request.report_type,
        **generation_options
    )

    if generate_request.auto_distribute and generate_request.distribution_list:
        try:
            bulk_distribute_report(
                audit_report_id=report["id"],
                recipients=generate_request.distribution_list,
                distribution_method="email",
                distribution_format="pdf",
                distributed_by=str(current_user.id)
            )
        except Exception as e:
            logging.warning(f"Auto-distribution failed: {e}")
    
    return report

@router_v1.patch("/audit-reports/{report_id}",
    summary="Update audit report",
    description="Update details of an existing audit report and create a new version",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def update_existing_audit_report(
    report_id: str = Path(..., description="Audit report UUID"),
    update_data: AuditReportUpdate = Body(..., description="Fields to update"),
    change_description: str = Body(..., description="Description of changes made", embed=True),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    update_dict = update_data.model_dump(exclude_unset=True)

    updated_report = update_audit_report(report_id, update_dict)

    if update_dict:
        create_audit_report_version(
            audit_report_id=report_id,
            changed_by=str(current_user.id),
            change_description=change_description,
            change_type="draft_update",
            report_snapshot=updated_report
        )
    
    return updated_report

@router_v1.put("/audit-reports/{report_id}/status",
    summary="Update audit report status",
    description="Change the status of an audit report (e.g., to 'finalized', 'approved')",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def update_audit_report_status(
    report_id: str = Path(..., description="Audit report UUID"),
    status_update: AuditReportStatusUpdate = Body(..., description="New status data"),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    update_data = {"report_status": status_update.new_status}

    if status_update.new_status == "approved":
        update_data["approved_by"] = str(current_user.id)
    elif status_update.new_status == "finalized":
        update_data["report_finalized_at"] = datetime.now(timezone.utc).isoformat()
    
    updated_report = update_audit_report(report_id, update_data)

    create_audit_report_version(
        audit_report_id=report_id,
        changed_by=str(current_user.id),
        change_description=f"Status changed to {status_update.new_status}" + (f": {status_update.notes}" if status_update.notes else ""),
        change_type="approval_change",
        report_snapshot=updated_report
    )
    
    return updated_report

@router_v1.delete("/audit-reports/{report_id}",
    summary="Delete audit report",
    description="Delete (archive) an audit report",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def delete_existing_audit_report(
    report_id: str = Path(..., description="Audit report UUID"),
    hard_delete: bool = Query(False, description="If true, permanently delete (not recommended)"),
    current_user: UserResponse = Depends(require_admin)
) -> Dict[str, Any]:
    return delete_audit_report(report_id, soft_delete=not hard_delete)

@router_v1.post("/audit-reports/search",
    summary="Search audit reports",
    description="Advanced search for audit reports with multiple filters",
    response_model=List[Dict[str, Any]],
    tags=["Audit Reports"],
)
def search_audit_reports(
    search_request: AuditReportSearchRequest = Body(..., description="Search criteria"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> List[Dict[str, Any]]:
    return list_audit_reports(
        skip=search_request.skip,
        limit=search_request.limit,
        compliance_domain=search_request.compliance_domain,
        report_type=search_request.report_type,
        report_status=search_request.report_status,
        user_id=str(search_request.user_id) if search_request.user_id else None,
        audit_session_id=str(search_request.audit_session_id) if search_request.audit_session_id else None,
        target_audience=search_request.target_audience,
        confidentiality_level=search_request.confidentiality_level,
        generated_after=search_request.generated_after,
        generated_before=search_request.generated_before
    )

@router_v1.get("/audit-reports/statistics",
    summary="Get audit report statistics",
    description="Get comprehensive statistics about audit reports",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def get_audit_report_statistics_endpoint(
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    start_date: Optional[datetime] = Query(None, description="Filter reports generated after this date"),
    end_date: Optional[datetime] = Query(None, description="Filter reports generated before this date"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return get_audit_report_statistics(
        compliance_domain=compliance_domain,
        user_id=user_id,
        start_date=start_date,
        end_date=end_date
    )

@router_v1.get("/audit-reports/{report_id}/versions",
    summary="List audit report versions",
    description="Get all versions of a specific audit report",
    response_model=List[Dict[str, Any]],
    tags=["Audit Reports"],
)
def get_audit_report_versions(
    report_id: str = Path(..., description="Audit report UUID"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> List[Dict[str, Any]]:
    return list_audit_report_versions(report_id, skip, limit)

@router_v1.get("/audit-reports/{report_id}/versions/latest",
    summary="Get latest audit report version",
    description="Get the most recent version of an audit report",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def get_latest_audit_report_version_endpoint(
    report_id: str = Path(..., description="Audit report UUID"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return get_latest_audit_report_version(report_id)

@router_v1.get("/audit-reports/{report_id}/versions/{version_number}",
    summary="Get audit report version by number",
    description="Get a specific version of an audit report",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def get_audit_report_version_by_number_endpoint(
    report_id: str = Path(..., description="Audit report UUID"),
    version_number: int = Path(..., description="Version number", ge=1),
    current_user: UserResponse = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return get_audit_report_version_by_number(report_id, version_number)

@router_v1.get("/audit-reports/{report_id}/versions/compare/{version1}/{version2}",
    summary="Compare audit report versions",
    description="Compare two versions of an audit report",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def compare_audit_report_versions_endpoint(
    report_id: str = Path(..., description="Audit report UUID"),
    version1: int = Path(..., description="First version number", ge=1),
    version2: int = Path(..., description="Second version number", ge=1),
    current_user: UserResponse = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return compare_audit_report_versions(report_id, version1, version2)

@router_v1.post("/audit-reports/{report_id}/versions/{version_number}/restore",
    summary="Restore audit report to previous version",
    description="Restore an audit report to a previous version",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def restore_audit_report_version_endpoint(
    report_id: str = Path(..., description="Audit report UUID"),
    version_number: int = Path(..., description="Version number to restore to", ge=1),
    restore_reason: str = Body(..., description="Reason for restoration", embed=True),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    return restore_audit_report_version(report_id, version_number, str(current_user.id), restore_reason)

@router_v1.get("/audit-reports/{report_id}/versions/history",
    summary="Get version history summary",
    description="Get a summary of version history for an audit report",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def get_audit_report_version_history_summary(
    report_id: str = Path(..., description="Audit report UUID"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return get_version_history_summary(report_id)

@router_v1.get("/audit-reports/distributions",
    summary="List all audit report distributions",
    description="Get paginated audit report distributions with optional filtering",
    response_model=List[Dict[str, Any]],
    tags=["Audit Reports"],
)
def get_all_audit_report_distributions(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    audit_report_id: Optional[str] = Query(None, description="Filter by audit report ID"),
    distributed_to: Optional[str] = Query(None, description="Filter by recipient"),
    distribution_method: Optional[str] = Query(None, description="Filter by distribution method"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> List[Dict[str, Any]]:
    return list_audit_report_distributions(
        audit_report_id=audit_report_id,
        distributed_to=distributed_to,
        distribution_method=distribution_method,
        is_active=is_active,
        skip=skip,
        limit=limit
    )

@router_v1.get("/audit-reports/{report_id}/distributions",
    summary="Get distributions for specific report",
    description="Get all distributions for a specific audit report",
    response_model=List[Dict[str, Any]],
    tags=["Audit Reports"],
)
def get_audit_report_distributions(
    report_id: str = Path(..., description="Audit report UUID"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> List[Dict[str, Any]]:
    return get_distributions_by_report_id(report_id)

@router_v1.post("/audit-reports/{report_id}/distribute",
    summary="Distribute audit report",
    description="Create a new distribution for an audit report",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
    status_code=201
)
def distribute_audit_report(
    report_id: str = Path(..., description="Audit report UUID"),
    distribution_data: AuditReportDistributionCreate = Body(..., description="Distribution details"),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    return create_audit_report_distribution(
        audit_report_id=report_id,
        distributed_to=distribution_data.distributed_to,
        distribution_method=distribution_data.distribution_method,
        distribution_format=distribution_data.distribution_format,
        distributed_by=str(current_user.id),
        external_reference=distribution_data.external_reference,
        expiry_date=distribution_data.expiry_date
    )

@router_v1.post("/audit-reports/{report_id}/distribute/bulk",
    summary="Bulk distribute audit report",
    description="Distribute an audit report to multiple recipients",
    response_model=List[Dict[str, Any]],
    tags=["Audit Reports"],
    status_code=201
)
def bulk_distribute_audit_report(
    report_id: str = Path(..., description="Audit report UUID"),
    recipients: List[str] = Body(..., description="List of recipient emails"),
    distribution_method: str = Body("email", description="Distribution method"),
    distribution_format: str = Body("pdf", description="Distribution format"),
    expiry_date: Optional[datetime] = Body(None, description="Expiry date for access"),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> List[Dict[str, Any]]:
    return bulk_distribute_report(
        audit_report_id=report_id,
        recipients=recipients,
        distribution_method=distribution_method,
        distribution_format=distribution_format,
        distributed_by=str(current_user.id),
        expiry_date=expiry_date
    )

@router_v1.post("/audit-report-distributions/{distribution_id}/access",
    summary="Log distribution access",
    description="Log access to a distributed audit report",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def log_audit_report_distribution_access(
    request: Request,
    distribution_id: str = Path(..., description="Distribution UUID"),
    access_log: AuditReportAccessLogRequest = Body(..., description="Access log data")
) -> Dict[str, Any]:
    ip_address = access_log.access_ip_address or (request.client.host if request.client else None)
    user_agent = access_log.user_agent or request.headers.get("user-agent")
    
    return log_distribution_access(
        distribution_id=distribution_id,
        access_ip_address=ip_address,
        user_agent=user_agent
    )

@router_v1.put("/audit-report-distributions/{distribution_id}/deactivate",
    summary="Deactivate distribution",
    description="Deactivate (revoke access to) a distribution",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def deactivate_audit_report_distribution(
    distribution_id: str = Path(..., description="Distribution UUID"),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    return deactivate_distribution(distribution_id, str(current_user.id))

@router_v1.put("/audit-report-distributions/{distribution_id}/reactivate",
    summary="Reactivate distribution",
    description="Reactivate a previously deactivated distribution",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def reactivate_audit_report_distribution(
    distribution_id: str = Path(..., description="Distribution UUID"),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    return reactivate_distribution(distribution_id, str(current_user.id))

@router_v1.put("/audit-report-distributions/{distribution_id}/expiry",
    summary="Update distribution expiry",
    description="Update the expiry date of a distribution",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def update_audit_report_distribution_expiry(
    distribution_id: str = Path(..., description="Distribution UUID"),
    new_expiry_date: Optional[datetime] = Body(..., description="New expiry date (null for no expiry)", embed=True),
    current_user: UserResponse = Depends(require_compliance_officer_or_admin)
) -> Dict[str, Any]:
    return update_distribution_expiry(distribution_id, new_expiry_date, str(current_user.id))

@router_v1.get("/audit-report-distributions/{distribution_id}",
    summary="Get distribution by ID",
    description="Get detailed information about a specific distribution",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def get_audit_report_distribution(
    distribution_id: str = Path(..., description="Distribution UUID"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return get_audit_report_distribution_by_id(distribution_id)

@router_v1.get("/audit-report-distributions/{distribution_id}/access-summary",
    summary="Get distribution access summary",
    description="Get access summary and analytics for a distribution",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def get_audit_report_distribution_access_summary(
    distribution_id: str = Path(..., description="Distribution UUID"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return get_distribution_access_summary(distribution_id)

@router_v1.delete("/audit-report-distributions/{distribution_id}",
    summary="Delete distribution",
    description="Permanently delete a distribution record",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def delete_audit_report_distribution(
    distribution_id: str = Path(..., description="Distribution UUID"),
    current_user: UserResponse = Depends(require_admin)
) -> Dict[str, Any]:
    return delete_distribution(distribution_id)

@router_v1.get("/audit-report-distributions/statistics",
    summary="Get distribution statistics",
    description="Get comprehensive statistics about audit report distributions",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def get_audit_report_distribution_statistics(
    audit_report_id: Optional[str] = Query(None, description="Filter by audit report ID"),
    start_date: Optional[datetime] = Query(None, description="Filter distributions created after this date"),
    end_date: Optional[datetime] = Query(None, description="Filter distributions created before this date"),
    current_user: UserResponse = Depends(get_current_active_user)
) -> Dict[str, Any]:
    return get_distribution_statistics(
        audit_report_id=audit_report_id,
        start_date=start_date,
        end_date=end_date
    )

@router_v1.post("/audit-report-distributions/cleanup-expired",
    summary="Cleanup expired distributions",
    description="Automatically deactivate all expired distributions",
    response_model=Dict[str, Any],
    tags=["Audit Reports"],
)
def cleanup_expired_audit_report_distributions(
    current_user: UserResponse = Depends(require_admin)
) -> Dict[str, Any]:
    return cleanup_expired_distributions()

app.include_router(router_v1)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))