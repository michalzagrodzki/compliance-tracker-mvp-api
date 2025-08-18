import time
import uuid
import logging
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse

from auth.decorators import ValidatedUser, authorize
from security.input_validator import validate_and_secure_query_request
from services.authentication import authenticate_and_authorize
from services.audit_log import create_audit_log
from services.audit_sessions import get_audit_session_by_id, update_audit_session
from services.chat_history import insert_chat_history
from services.history import get_history
from services.qa import answer_question
from services.schemas import QueryRequest, QueryResponse
from services.streaming import stream_answer_sync

router = APIRouter(tags=["RAG"])


def _build_query_metadata(sources, compliance_domain, document_version, document_tags):
    """
    Build aggregated metadata from source documents for the query endpoint.
    Similar to the streaming approach but adapted for the sources format from answer_question.
    """
    from typing import List, Dict, Any, Optional
    
    if not sources:
        return {}
    
    # Collect metadata from all source documents
    source_filenames = set()
    source_domains = set()
    source_versions = set()
    all_tags = set()
    authors = set()
    titles = set()
    
    # Statistics
    total_similarity_score = 0.0
    best_match_score = 0.0
    
    document_details = []
    
    for source in sources:
        metadata = source.get("metadata", {})
        
        # Collect unique values from metadata
        if metadata.get("source_filename"):
            source_filenames.add(metadata["source_filename"])
        if metadata.get("compliance_domain"):
            source_domains.add(metadata["compliance_domain"])
        if metadata.get("document_version"):
            source_versions.add(metadata["document_version"])
        if metadata.get("document_tags"):
            all_tags.update(metadata["document_tags"])
        if metadata.get("author"):
            authors.add(metadata["author"])
        if metadata.get("title"):
            titles.add(metadata["title"])
            
        # Calculate similarity statistics
        similarity = float(source.get("similarity", 0))
        total_similarity_score += similarity
        best_match_score = max(best_match_score, similarity)
        
        # Collect individual document details
        document_details.append({
            "id": source.get("id"),
            "source_filename": metadata.get("source_filename"),
            "compliance_domain": metadata.get("compliance_domain"),
            "document_version": metadata.get("document_version"),
            "similarity": similarity,
            "chunk_index": metadata.get("chunk_index", 0)
        })
    
    # Calculate average similarity
    avg_similarity = total_similarity_score / len(sources) if sources else 0.0
    
    return {
        "query_metadata": {
            "requested_compliance_domain": compliance_domain,
            "requested_document_version": document_version,
            "requested_document_tags": document_tags or [],
            "sources_analyzed": len(sources)
        },
        "document_coverage": {
            "unique_source_files": list(source_filenames),
            "unique_compliance_domains": list(source_domains),
            "unique_document_versions": list(source_versions),
            "all_document_tags": list(all_tags),
            "unique_authors": list(authors),
            "unique_titles": list(titles),
            "total_sources": len(sources)
        },
        "similarity_metrics": {
            "best_match_score": round(best_match_score, 4),
            "average_similarity": round(avg_similarity, 4),
            "total_similarity": round(total_similarity_score, 4)
        },
        "document_details": document_details
    }


@router.post("/query",
    response_model=QueryResponse,
    summary="Query the knowledge base with compliance tracking",
    description="Retrieval-Augmented Generation over ingested documents with full audit trail logging."
)
@authorize(domains=["ISO27001"], allowed_roles=["admin", "compliance_officer"], check_active=True)
def query_qa(
    req: QueryRequest,
    request: Request,
    current_user: ValidatedUser = None
) -> QueryResponse:
    validated_req = validate_and_secure_query_request(req, request)
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

    answer, sources = answer_question(
        question=validated_req.question,
        match_threshold=validated_req.match_threshold,
        match_count=validated_req.match_count,
        compliance_domain=compliance_domain,
        document_version=getattr(req, 'document_version'),
        document_tags=getattr(req, 'document_tags', [])
    )
    
    end_time = time.time()
    response_time_ms = int((end_time - start_time) * 1000)
    
    source_document_ids = [source["id"] for source in sources]
    
    aggregated_metadata = _build_query_metadata(sources, compliance_domain, getattr(req, 'document_version'), getattr(req, 'document_tags', []))

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
            user_id=current_user.id,
            response_time_ms=response_time_ms,
            total_tokens_used=None,
            metadata=aggregated_metadata
        )
    except Exception as e:
        logging.warning(f"Failed to log chat history: {e}")
    
    # Log document access for audit trail
    if req.audit_session_id and source_document_ids:
        try:
            for doc_id in source_document_ids:
                create_audit_log(
                    object_type="document",
                    user_id=current_user.id,
                    object_id=doc_id,
                    action="reference",
                    compliance_domain=compliance_domain,
                    audit_session_id=req.audit_session_id,
                    risk_level="medium",
                    details={"query_text": req.question, "answer": answer},
                    ip_address=ip_address,
                    user_agent=user_agent
                )
        except Exception as e:
            logging.warning(f"Failed to log audit log: {e}")
    
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
        response_time_ms=response_time_ms,
        metadata=aggregated_metadata
    )


@router.post("/query-stream",
    response_model=None,
    summary="Streamed Q&A with compliance tracking and history",
    description="Streamed responses with full audit trail logging and compliance domain filtering."
)
def query_stream(
    req: QueryRequest,
    request: Request,
):
    current_user = authenticate_and_authorize(
        request=request,
        allowed_roles=["admin", "compliance_officer"],
        domains=["ISO27001"],
        check_active=True,
    )

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
        source_document_ids = []
        metadata = {}

        for token_data in stream_answer_sync(
            question=req.question,
            conversation_id=conversation_id,
            history=history,
            audit_session_id=req.audit_session_id,
            compliance_domain=compliance_domain,
            match_threshold=getattr(req, 'match_threshold', 0.75),
            match_count=getattr(req, 'match_count', 5),
            user_id=getattr(req, 'user_id', None),
            document_version=getattr(req, 'document_version'),
            document_tags=getattr(req, 'document_tags', [])
        ):
            if isinstance(token_data, dict):
                if "source_document_ids" in token_data:
                    source_document_ids = token_data["source_document_ids"]
                if "metadata" in token_data:
                    metadata = token_data["metadata"]
                continue
            
            yield token_data
        
        if req.audit_session_id and source_document_ids:
            try:
                for doc_id in source_document_ids:
                    create_audit_log(
                        object_type="document",
                        user_id=current_user.id,
                        object_id=doc_id,
                        action="reference",
                        compliance_domain=compliance_domain,
                        audit_session_id=req.audit_session_id,
                        risk_level="medium",
                        details={"query_text": req.question},
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