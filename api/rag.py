import time
import uuid
import logging
import json
from typing import Dict, Any, Union, Iterator
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse

from auth.decorators import ValidatedUser, authorize
from security.input_validator import validate_and_secure_query_request
from services.authentication import authenticate_and_authorize
from services.audit_sessions import get_audit_session_by_id, update_audit_session
from services.history import get_history
from services.schemas import QueryRequest, QueryResponse
from dependencies import RAGServiceDep
from common.exceptions import ValidationException, AuthorizationException, BusinessLogicException

router = APIRouter(tags=["RAG"])


@router.post("/query",
    response_model=QueryResponse,
    summary="Query the knowledge base with compliance tracking",
    description="Retrieval-Augmented Generation over ingested documents with full audit trail logging."
)
@authorize(domains=["ISO27001"], allowed_roles=["admin", "compliance_officer"], check_active=True)
async def query_qa(
    req: QueryRequest,
    request: Request,
    rag_service: RAGServiceDep,
    current_user: ValidatedUser = None
) -> QueryResponse:
    try:
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

        conversation_id = req.conversation_id or str(uuid.uuid4())

        # Use RAG service to answer question
        answer, source_docs, metadata = await rag_service.answer_question(
            question=validated_req.question,
            user_id=current_user.id,
            match_threshold=validated_req.match_threshold,
            match_count=validated_req.match_count,
            compliance_domain=compliance_domain,
            document_versions=getattr(req, 'document_versions', None),
            document_tags=getattr(req, 'document_tags', None),
            conversation_id=conversation_id,
            audit_session_id=req.audit_session_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        end_time = time.time()
        response_time_ms = int((end_time - start_time) * 1000)
        
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
    
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)
    except Exception as e:
        logging.error(f"Unexpected error in query endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="An unexpected error occurred while processing your request")

    return QueryResponse(
        answer=answer,
        source_docs=source_docs,
        conversation_id=conversation_id,
        audit_session_id=req.audit_session_id,
        compliance_domain=compliance_domain,
        response_time_ms=response_time_ms,
        metadata=metadata
    )


@router.post("/query-stream",
    response_model=None,
    summary="Streamed Q&A with compliance tracking and history",
    description="Streamed responses with full audit trail logging and compliance domain filtering."
)
async def query_stream(
    req: QueryRequest,
    request: Request,
    rag_service: RAGServiceDep
):
    try:
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

        def event_generator() -> Iterator[Union[str, Dict[str, Any]]]:
            try:
                for token_data in rag_service.stream_answer(
                    question=req.question,
                    user_id=current_user.id,
                    conversation_id=conversation_id,
                    history=history,
                    match_threshold=getattr(req, 'match_threshold', 0.75),
                    match_count=getattr(req, 'match_count', 5),
                    compliance_domain=compliance_domain,
                    document_versions=getattr(req, 'document_versions', None),
                    document_tags=getattr(req, 'document_tags', None),
                    audit_session_id=req.audit_session_id,
                    ip_address=ip_address,
                    user_agent=user_agent
                ):
                    # Only stream text chunks; drop metadata objects
                    if isinstance(token_data, (dict, list)):
                        continue
                    yield token_data
                
                # Update audit session query count after streaming completes
                if req.audit_session_id and audit_session_data:
                    try:
                        current_count = audit_session_data.get("total_queries", 0)
                        update_audit_session(
                            session_id=req.audit_session_id,
                            total_queries=current_count + 1
                        )
                    except Exception as e:
                        logging.warning(f"Failed to update audit session query count: {e}")
            
            except ValidationException as e:
                yield f"Error: {e.detail}"
            except AuthorizationException as e:
                yield f"Error: Access denied - {e.detail}"
            except BusinessLogicException as e:
                yield f"Error: {e.detail}"
            except Exception as e:
                logging.error(f"Streaming error: {e}", exc_info=True)
                yield f"Error: An unexpected error occurred while processing your request"
    
    except Exception as e:
        logging.error(f"Stream setup error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to initialize streaming response")

    return StreamingResponse(
        event_generator(),
        media_type="text/markdown; charset=utf-8",
        headers={
            "x-conversation-id": conversation_id,
            "x-audit-session-id": req.audit_session_id or "",
            "x-compliance-domain": compliance_domain or ""
        }
    )
