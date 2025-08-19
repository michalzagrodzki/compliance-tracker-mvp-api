from typing import Any, Optional
from fastapi import APIRouter, Query

from auth.decorators import authorize
from dependencies import ChatHistoryServiceDep
from services.schemas import ChatHistoryItem
from entities.chat_history import ChatHistoryFilter
from common.responses import create_paginated_response

router = APIRouter(prefix="/history", tags=["History"])


@router.get("/item/{item_id}",
    summary="Get single chat history item by ID",
    description="Returns a single chat history entry by its unique ID",
    response_model=ChatHistoryItem
)
@authorize(domains=["ISO27001"], allowed_roles=["admin", "compliance_officer"], check_active=True)
async def read_history_item(
    item_id: int,
    history_service: ChatHistoryServiceDep = None,
) -> ChatHistoryItem:
    item = await history_service.get_by_id(item_id)
    return ChatHistoryItem(
        id=str(item.id),
        conversation_id=item.conversation_id,
        question=item.question,
        answer=item.answer,
        created_at=item.created_at,
        audit_session_id=item.audit_session_id,
        compliance_domain=item.compliance_domain,
        source_document_ids=item.source_document_ids,
        match_threshold=item.match_threshold,
        match_count=item.match_count,
        user_id=item.user_id,
        response_time_ms=item.response_time_ms,
        total_tokens_used=item.total_tokens_used,
        metadata=item.metadata,
    )

@router.get("/{conversation_id}",
    summary="Get chat history for a conversation",
    description="Retrieves paginated chat history for a specific conversation ID with optional filtering"
)
@authorize(domains=["ISO27001"], allowed_roles=["admin", "compliance_officer"], check_active=True)
async def read_history(
    conversation_id: str,
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session UUID"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain code"),
    user_id: Optional[str] = Query(None, description="Filter by user UUID"),
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination"),
    limit: int = Query(10, ge=1, le=1000, description="Maximum number of records to return"),
    history_service: ChatHistoryServiceDep = None,
) -> Any:
    filters = ChatHistoryFilter(
        conversation_id=conversation_id,
        audit_session_id=audit_session_id,
        compliance_domain=compliance_domain,
        user_id=user_id,
    )
    items = await history_service.list(skip=skip, limit=limit, filters=filters)
    total = await history_service.count(filters=filters)
    data = [
        ChatHistoryItem(
            id=str(i.id),
            conversation_id=i.conversation_id,
            question=i.question,
            answer=i.answer,
            created_at=i.created_at,
            audit_session_id=i.audit_session_id,
            compliance_domain=i.compliance_domain,
            source_document_ids=i.source_document_ids,
            match_threshold=i.match_threshold,
            match_count=i.match_count,
            user_id=i.user_id,
            response_time_ms=i.response_time_ms,
            total_tokens_used=i.total_tokens_used,
            metadata=i.metadata,
        ).model_dump(mode="json")
        for i in items
    ]
    return create_paginated_response(
        data=data,
        total=total,
        skip=skip,
        limit=limit,
        filters_applied={
            "conversation_id": conversation_id,
            "audit_session_id": audit_session_id,
            "compliance_domain": compliance_domain,
            "user_id": user_id,
        },
    )

@router.get("/audit-sessions/{audit_session_id}",
    summary="Get chat history for an audit session",
    description="Retrieves chat history filtered by audit session ID with pagination"
)
@authorize(domains=["ISO27001"], allowed_roles=["admin", "compliance_officer"], check_active=True)
async def read_audit_session_history(
    audit_session_id: str,
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination"),
    limit: int = Query(10, ge=1, le=1000, description="Maximum number of records to return"),
    history_service: ChatHistoryServiceDep = None,
) -> Any:
    filters = ChatHistoryFilter(audit_session_id=audit_session_id, compliance_domain=compliance_domain)
    items = await history_service.list(skip=skip, limit=limit, filters=filters)
    total = await history_service.count(filters=filters)
    data = [
        ChatHistoryItem(
            id=str(i.id),
            conversation_id=i.conversation_id,
            question=i.question,
            answer=i.answer,
            created_at=i.created_at,
            audit_session_id=i.audit_session_id,
            compliance_domain=i.compliance_domain,
            source_document_ids=i.source_document_ids,
            match_threshold=i.match_threshold,
            match_count=i.match_count,
            user_id=i.user_id,
            response_time_ms=i.response_time_ms,
            total_tokens_used=i.total_tokens_used,
            metadata=i.metadata,
        ).model_dump(mode="json")
        for i in items
    ]
    return create_paginated_response(
        data=data,
        total=total,
        skip=skip,
        limit=limit,
        filters_applied={
            "audit_session_id": audit_session_id,
            "compliance_domain": compliance_domain,
        },
    )

@router.get("/compliance-domains/{domain_code}",
    summary="Get chat history for a compliance domain",
    description="Retrieves chat history filtered by compliance domain with pagination"
)
@authorize(domains=["ISO27001"], allowed_roles=["admin", "compliance_officer"], check_active=True)
async def read_domain_history(
    domain_code: str,
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session"),
    user_id: Optional[str] = Query(None, description="Filter by user"),
    limit: Optional[int] = Query(100, ge=1, le=1000, description="Limit number of records"),
    skip: Optional[int] = Query(0, ge=0, description="Skip number of records for pagination"),
    history_service: ChatHistoryServiceDep = None,
) -> Any:
    filters = ChatHistoryFilter(
        compliance_domain=domain_code,
        audit_session_id=audit_session_id,
        user_id=user_id,
    )
    items = await history_service.list(skip=skip or 0, limit=limit or 100, filters=filters)
    total = await history_service.count(filters=filters)
    data = [
        ChatHistoryItem(
            id=str(i.id),
            conversation_id=i.conversation_id,
            question=i.question,
            answer=i.answer,
            created_at=i.created_at,
            audit_session_id=i.audit_session_id,
            compliance_domain=i.compliance_domain,
            source_document_ids=i.source_document_ids,
            match_threshold=i.match_threshold,
            match_count=i.match_count,
            user_id=i.user_id,
            response_time_ms=i.response_time_ms,
            total_tokens_used=i.total_tokens_used,
            metadata=i.metadata,
        ).model_dump(mode="json")
        for i in items
    ]
    return create_paginated_response(
        data=data,
        total=total,
        skip=skip or 0,
        limit=limit or 100,
        filters_applied={
            "compliance_domain": domain_code,
            "audit_session_id": audit_session_id,
            "user_id": user_id,
        },
    )

@router.get("/users/{user_id}",
    summary="Get chat history for a user",
    description="Retrieves chat history for a specific user with pagination and filtering options"
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def read_user_history(
    user_id: str,
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session"),
    limit: Optional[int] = Query(100, ge=1, le=1000, description="Limit number of records"),
    skip: Optional[int] = Query(0, ge=0, description="Skip number of records for pagination"),
    history_service: ChatHistoryServiceDep = None,
) -> Any:
    filters = ChatHistoryFilter(
        user_id=user_id,
        compliance_domain=compliance_domain,
        audit_session_id=audit_session_id,
    )
    items = await history_service.list(skip=skip or 0, limit=limit or 100, filters=filters)
    total = await history_service.count(filters=filters)
    data = [
        ChatHistoryItem(
            id=str(i.id),
            conversation_id=i.conversation_id,
            question=i.question,
            answer=i.answer,
            created_at=i.created_at,
            audit_session_id=i.audit_session_id,
            compliance_domain=i.compliance_domain,
            source_document_ids=i.source_document_ids,
            match_threshold=i.match_threshold,
            match_count=i.match_count,
            user_id=i.user_id,
            response_time_ms=i.response_time_ms,
            total_tokens_used=i.total_tokens_used,
            metadata=i.metadata,
        ).model_dump(mode="json")
        for i in items
    ]
    return create_paginated_response(
        data=data,
        total=total,
        skip=skip or 0,
        limit=limit or 100,
        filters_applied={
            "user_id": user_id,
            "compliance_domain": compliance_domain,
            "audit_session_id": audit_session_id,
        },
    )
