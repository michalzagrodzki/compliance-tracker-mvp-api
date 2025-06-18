import datetime
import os
from pathlib import Path
import uuid
from fastapi import FastAPI, HTTPException, APIRouter, File, UploadFile, Form, Path, Body, Query
from services.chat_history import get_audit_session_history, get_chat_history, get_domain_history, get_user_history
from services.compliance_domain import get_compliance_domain_by_code, list_compliance_domains
from services.db_check import check_database_connection
from services.document import (
    list_documents, 
    get_documents_by_source_filename,
    get_documents_by_compliance_domain, 
    get_documents_by_version,
    get_documents_by_domain_and_version
)
from services.schemas import (
    ComplianceDomain,
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
from typing import Any, List, Dict, Optional
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
from datetime import datetime, timezone
from services.audit_sessions import ( delete_audit_session, get_audit_session_statistics )

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
    summary="Query the knowledge base",
    description="Retrieval-Augmented Generation over ingested documents.",
    tags=["RAG"],
)
def query_qa(req: QueryRequest) -> QueryResponse:
    answer, sources = answer_question(req.question, match_threshold=0.75, match_count=5)
    return QueryResponse(answer=answer, source_docs=sources)

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
    
@router_v1.post("/query-stream",
    response_model=None,
    summary="Streamed Q&A with history",
    tags=["RAG"],
)
def query_stream(req: QueryRequest):
    # 0) ensure we have a UUID to track this conversation
    if req.conversation_id:
        try:
            uuid.UUID(req.conversation_id)
            conversation_id = req.conversation_id
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid conversation_id format (must be UUID)")
    else:
        conversation_id = str(uuid.uuid4())

    # 1) load history
    history = get_history(conversation_id)

    # 2) stream tokens, then append history at the end
    def event_generator():
        for token in stream_answer_sync(req.question, conversation_id, history):
            yield token

    return StreamingResponse(
        event_generator(),
        media_type="text/plain; charset=utf-8",
        headers={"x-conversation-id": conversation_id}
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
    session_data: AuditSessionCreate = Body(..., description="Audit session data")
) -> AuditSessionResponse:
    return create_audit_session(
        user_id=session_data.user_id,
        session_name=session_data.session_name,
        compliance_domain=session_data.compliance_domain,
        ip_address=session_data.ip_address,
        user_agent=session_data.user_agent
    )

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

app.include_router(router_v1)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))