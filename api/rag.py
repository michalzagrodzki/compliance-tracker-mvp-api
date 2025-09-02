import time
import uuid
import logging
import json
from typing import Dict, Any, Union, Iterator
from fastapi import APIRouter, Request, HTTPException, Header, Response
from fastapi.responses import StreamingResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from auth.decorators import ValidatedUser, authorize
from security.input_validator import safe_stream, validate_and_secure_query_request
from security.endpoint_validator import ensure_json_request, normalize_user_agent, compute_fingerprint, require_idempotency, stable_fingerprint, store_idempotency
from services.authentication import authenticate_and_authorize
from services.audit_sessions import get_audit_session_by_id, update_audit_session
from dependencies import ChatHistoryServiceDep
from entities.chat_history import ChatHistoryFilter
from services.schemas import QueryRequest, QueryResponse
from dependencies import RAGServiceDep
from common.exceptions import ValidationException, AuthorizationException, BusinessLogicException

router = APIRouter(tags=["RAG"])
limiter = Limiter(key_func=get_remote_address)

# Security configuration constants
IDEMPOTENCY_TTL_SECONDS = 24 * 3600
ALLOWED_QUERY_FIELDS = {
    "question",
    "conversation_id", 
    "audit_session_id",
    "match_threshold",
    "match_count",
    "compliance_domain",
    "document_versions",
    "document_tags"
}


@router.post("/query",
    response_model=QueryResponse,
    summary="Query the knowledge base with compliance tracking",
    description="Retrieval-Augmented Generation over ingested documents with full audit trail logging."
)
@limiter.limit("10/minute")
async def query_qa(
    req: QueryRequest,
    request: Request,
    response: Response,
    rag_service: RAGServiceDep,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", convert_underscores=False)
) -> QueryResponse:
    """
    Secure Q&A endpoint with comprehensive input validation,
    idempotency protection, and audit trail compliance.
    """
    try:
        # Authentication and authorization
        current_user = authenticate_and_authorize(
            request=request,
            allowed_roles=["admin", "compliance_officer"],
            domains=["ISO27001"],
            check_active=True,
        )

        # NIST SP 800-53 SI-10: Input validation and sanitization
        ensure_json_request(request)
        validated_req = validate_and_secure_query_request(req, request)
        ua = normalize_user_agent(request.headers.get("user-agent"))
        
        start_time = time.time()
        
        # Extract client information for audit trail
        ip_address = request.client.host if request.client else None
        
        # Convert request data to dict for field filtering (OWASP API3:2023)
        if hasattr(req, "model_dump"):
            payload = req.model_dump()
        elif hasattr(req, "dict"):
            payload = req.dict()
        else:
            payload = dict(req)
        
        # Filter to allowed fields only
        filtered_payload = {k: v for k, v in payload.items() if k in ALLOWED_QUERY_FIELDS}
        
        # Parameter validation
        match_threshold = float(filtered_payload.get("match_threshold", 0.75))
        if not (0.0 <= match_threshold <= 1.0):
            raise HTTPException(400, "match_threshold must be between 0.0 and 1.0")

        match_count = int(filtered_payload.get("match_count", 5))
        if not (1 <= match_count <= 10):
            raise HTTPException(400, "match_count must be between 1 and 10")

        # UUID validation for conversation_id
        conversation_id = filtered_payload.get("conversation_id")
        if conversation_id:
            try:
                uuid.UUID(conversation_id)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid conversation_id format (must be UUID)")
        else:
            conversation_id = str(uuid.uuid4())
        
        # UUID validation for audit_session_id if provided
        audit_session_id = filtered_payload.get("audit_session_id")
        if audit_session_id:
            try:
                uuid.UUID(audit_session_id)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid audit_session_id format (must be UUID)")

        # Validate audit session if provided
        audit_session_data = None
        if audit_session_id:
            try:
                audit_session_data = get_audit_session_by_id(audit_session_id)
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
        elif filtered_payload.get('compliance_domain'):
            compliance_domain = filtered_payload['compliance_domain']

        # Idempotency protection for query operations
        query_fingerprint = stable_fingerprint({
            "operation": "query",
            "user_id": current_user.id if current_user else None,
            "conversation_id": conversation_id,
            "question_hash": validated_req.question,
            "compliance_domain": compliance_domain,
            "audit_session_id": audit_session_id,
            "match_threshold": match_threshold,
            "match_count": match_count
        })
        
        repo = request.app.state.idempotency_repo
        cached = require_idempotency(repo, idempotency_key, query_fingerprint)
        
        if cached:
            # Return cached response
            cached_response = cached.get("body", {})
            if "data" in cached_response:
                return QueryResponse(**cached_response["data"])
            return cached_response

        # Use RAG service to answer question with filtered parameters
        answer, source_docs, metadata = await rag_service.answer_question(
            question=validated_req.question,
            user_id=current_user.id if current_user else None,
            match_threshold=match_threshold,
            match_count=match_count,
            compliance_domain=compliance_domain,
            document_versions=filtered_payload.get('document_versions'),
            document_tags=filtered_payload.get('document_tags'),
            conversation_id=conversation_id,
            audit_session_id=audit_session_id,
            ip_address=ip_address,
            user_agent=ua
        )
        
        end_time = time.time()
        response_time_ms = int((end_time - start_time) * 1000)
        
        # Update audit session query count
        if audit_session_id and audit_session_data:
            try:
                current_count = audit_session_data.get("total_queries", 0)
                update_audit_session(
                    session_id=audit_session_id,
                    total_queries=current_count + 1
                )
            except Exception as e:
                logging.warning(f"Failed to update audit session query count: {e}")

        # Create response
        response_data = QueryResponse(
            answer=answer,
            source_docs=source_docs,
            conversation_id=conversation_id,
            audit_session_id=audit_session_id,
            compliance_domain=compliance_domain,
            response_time_ms=response_time_ms,
            metadata=metadata
        )

        # Store successful operation for idempotency
        if idempotency_key:
            store_idempotency(
                repo, 
                idempotency_key, 
                query_fingerprint,
                {"data": response_data.model_dump()},
                IDEMPOTENCY_TTL_SECONDS
            )

        # Set security response headers
        response.headers.update({
            "x-conversation-id": conversation_id,
            "x-audit-session-id": audit_session_id or "",
            "x-compliance-domain": compliance_domain or "",
            "x-content-type-options": "nosniff",
            "cache-control": "no-cache, no-store, must-revalidate",
            "pragma": "no-cache",
            "expires": "0"
        })

        return response_data
    
    except ValidationException as e:
        logging.warning(f"Request validation failed: {e.detail}")
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        logging.warning(f"Authorization failed: {e.detail}")
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        logging.warning(f"Business logic error: {e.detail}")
        raise HTTPException(status_code=500, detail=e.detail)
    except Exception as e:
        logging.error(f"Unexpected error in query endpoint: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="An unexpected error occurred while processing your request")


@router.post("/query-stream",
    response_model=None,
    summary="Streamed Q&A with compliance tracking and history",
    description="Streamed responses with full audit trail logging and compliance domain filtering."
)
@limiter.limit("10/minute")
async def query_stream(
    request_data: QueryRequest,
    request: Request,
    response: Response,
    rag_service: RAGServiceDep,
    history_service: ChatHistoryServiceDep,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", convert_underscores=False)
):
    """
    Secure streaming Q&A endpoint with comprehensive input validation,
    idempotency protection, and audit trail compliance.
    """
    try:
        current_user = authenticate_and_authorize(
            request=request,
            allowed_roles=["admin", "compliance_officer"],
            domains=["ISO27001"],
            check_active=True,
        )

        # NIST SP 800-53 SI-10: Input validation and sanitization
        ensure_json_request(request)
        validated_req = validate_and_secure_query_request(request_data, request)
        
        # Convert request data to dict for field filtering (OWASP API3:2023)
        if hasattr(request_data, "model_dump"):
            payload = request_data.model_dump()
        elif hasattr(request_data, "dict"):
            payload = request_data.dict()
        else:
            payload = dict(request_data)
        
        # Filter to allowed fields only
        filtered_payload = {k: v for k, v in payload.items() if k in ALLOWED_QUERY_FIELDS}

        match_threshold = float(filtered_payload.get("match_threshold", 0.75))
        if not (0.0 <= match_threshold <= 1.0):
            raise HTTPException(400, "match_threshold must be between 0.0 and 1.0")

        match_count = int(filtered_payload.get("match_count", 5))
        if not (1 <= match_count <= 10):
            raise HTTPException(400, "match_count must be between 1 and 50")

        conversation_id = filtered_payload.get("conversation_id")
        if conversation_id:
            try:
                uuid.UUID(conversation_id)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid conversation_id format (must be UUID)")
        else:
            conversation_id = str(uuid.uuid4())

        audit_session_id = filtered_payload.get("audit_session_id")
        if audit_session_id:
            try:
                uuid.UUID(audit_session_id)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid audit_session_id format (must be UUID)")

        audit_session_data = None
        if audit_session_id:
            try:
                audit_session_data = get_audit_session_by_id(audit_session_id)
                if not audit_session_data.get("is_active", False):
                    raise HTTPException(status_code=400, detail="Audit session is not active")
            except HTTPException as e:
                if e.status_code == 404:
                    raise HTTPException(status_code=400, detail="Invalid audit session ID")
                raise

        compliance_domain = None
        if audit_session_data:
            compliance_domain = audit_session_data.get("compliance_domain")
        elif filtered_payload.get('compliance_domain'):
            compliance_domain = filtered_payload['compliance_domain']

        stream_fingerprint = stable_fingerprint({
            "operation": "query_stream",
            "user_id": current_user.id if current_user else None,
            "conversation_id": conversation_id,
            "question_hash": validated_req.question,
            "compliance_domain": compliance_domain,
            "audit_session_id": audit_session_id
        })
        
        repo = request.app.state.idempotency_repo
        cached = require_idempotency(repo, idempotency_key, stream_fingerprint)
        
        if cached:
            response.headers.update(cached.get("headers", {}))
            return StreamingResponse(
                iter([cached.get("cached_response", "")]),
                media_type="text/markdown; charset=utf-8",
                headers=cached.get("headers", {})
            )
        # Build recent conversation history using the ChatHistoryService (DI)
        history_filters = ChatHistoryFilter(
            conversation_id=conversation_id,
            audit_session_id=audit_session_id,
            compliance_domain=compliance_domain,
        )
        recent_items = await history_service.list(skip=0, limit=10, filters=history_filters)
        history = [
            {"question": item.question, "answer": item.answer}
            for item in recent_items
        ]
        def event_generator() -> Iterator[Union[str, Dict[str, Any]]]:
            stream_content = []
            try:
                for token_data in safe_stream(rag_service.stream_answer(
                    question=validated_req.question,
                    user_id=current_user.id if current_user else None,
                    conversation_id=conversation_id,
                    history=history,
                    match_threshold=match_threshold,
                    match_count=match_count,
                    compliance_domain=compliance_domain,
                    document_versions=filtered_payload.get('document_versions'),
                    document_tags=filtered_payload.get('document_tags'),
                    audit_session_id=audit_session_id
                )) :
                    # Only stream text chunks; filter out metadata objects
                    if isinstance(token_data, (dict, list)):
                        continue
                    
                    # Sanitize token data before streaming
                    clean_token = str(token_data).replace('\x00', '')  # Remove null bytes
                    stream_content.append(clean_token)
                    yield clean_token
                
                # Update audit session query count after streaming completes
                if audit_session_id and audit_session_data:
                    try:
                        current_count = audit_session_data.get("total_queries", 0)
                        update_audit_session(
                            session_id=audit_session_id,
                            total_queries=current_count + 1
                        )
                    except Exception as e:
                        logging.warning(f"Failed to update audit session query count: {e}")
                
                # Store successful stream operation for idempotency
                if idempotency_key:
                    stream_headers = {
                        "x-conversation-id": conversation_id,
                        "x-audit-session-id": audit_session_id or "",
                        "x-compliance-domain": compliance_domain or "",
                    }
                    store_idempotency(
                        repo, 
                        idempotency_key, 
                        stream_fingerprint,
                        {
                            "cached_response": "".join(stream_content),
                            "headers": stream_headers
                        },
                        IDEMPOTENCY_TTL_SECONDS
                    )
                    
            except ValidationException as e:
                logging.warning(f"Validation error in streaming: {e.detail}")
                yield "Error: invalid request."
            except AuthorizationException as e:
                logging.warning(f"Authorization error in streaming: {e.detail}")
                yield "Error: Access denied"
            except BusinessLogicException as e:
                logging.warning(f"Business logic error in streaming: {e.detail}")
                yield "Error: invalid request."
            except Exception as e:
                logging.error(f"Unexpected streaming error: {e}", exc_info=True)
                yield f"Error: An unexpected error occurred while processing your request"

        stream_headers = {
            "x-conversation-id": conversation_id,
            "x-audit-session-id": audit_session_id or "",
            "x-compliance-domain": compliance_domain or "",
            "x-content-type-options": "nosniff",
            "cache-control": "no-cache, no-store, must-revalidate",
            "pragma": "no-cache",
            "expires": "0"
        }
        response.headers.update(stream_headers)

        return StreamingResponse(
            event_generator(),
            media_type="text/markdown; charset=utf-8",
            headers=stream_headers
        )
        
    except ValidationException as e:
        logging.warning(f"Request validation failed: {e.detail}")
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        logging.warning(f"Authorization failed: {e.detail}")
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        logging.warning(f"Business logic error: {e.detail}")
        raise HTTPException(status_code=500, detail=e.detail)
    except Exception as e:
        logging.error(f"Stream setup error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to initialize streaming response")
