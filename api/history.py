from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Query, Path

from auth.decorators import ValidatedUser, authorize
from services.chat_history import (
    get_chat_history_item,
    get_chat_history,
    get_audit_session_history,
    get_domain_history,
    get_user_history,
)
from services.schemas import ChatHistoryItem

router = APIRouter(prefix="/history", tags=["History"])


@router.get("/item/{item_id}",
    summary="Get single chat history item by ID",
    description="Returns a single chat history entry by its unique ID",
    response_model=ChatHistoryItem
)
@authorize(domains=["ISO27001"], allowed_roles=["admin", "compliance_officer"], check_active=True)
def read_history_item(
    item_id: int,
):
    return get_chat_history_item(item_id)

@router.get("/{conversation_id}",
    summary="Get chat history for a conversation",
    description="Retrieves paginated chat history for a specific conversation ID with optional filtering",
    response_model=List[ChatHistoryItem]
)
@authorize(domains=["ISO27001"], allowed_roles=["admin", "compliance_officer"], check_active=True)
def read_history(
    conversation_id: str,
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session UUID"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain code"),
    user_id: Optional[str] = Query(None, description="Filter by user UUID"),
    limit: Optional[int] = Query(None, ge=1, le=1000, description="Limit number of records"),
):
    return get_chat_history(
        conversation_id=conversation_id,
        audit_session_id=audit_session_id,
        compliance_domain=compliance_domain,
        user_id=user_id,
        limit=limit
    )

@router.get("/audit-sessions/{audit_session_id}",
    summary="Get chat history for an audit session",
    description="Retrieves chat history filtered by audit session ID with pagination",
    response_model=List[ChatHistoryItem]
)
@authorize(domains=["ISO27001"], allowed_roles=["admin", "compliance_officer"], check_active=True)
def read_audit_session_history(
    audit_session_id: str,
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
):
    return get_audit_session_history(
        audit_session_id=audit_session_id,
        compliance_domain=compliance_domain
    )

@router.get("/compliance-domains/{domain_code}",
    summary="Get chat history for a compliance domain",
    description="Retrieves chat history filtered by compliance domain with pagination",
    response_model=List[ChatHistoryItem]
)
@authorize(domains=["ISO27001"], allowed_roles=["admin", "compliance_officer"], check_active=True)
def read_domain_history(
    domain_code: str,
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session"),
    user_id: Optional[str] = Query(None, description="Filter by user"),
    limit: Optional[int] = Query(100, ge=1, le=1000, description="Limit number of records"),
    skip: Optional[int] = Query(0, ge=0, description="Skip number of records for pagination"),
) -> List[ChatHistoryItem]:
    return get_domain_history(
        domain_code=domain_code,
        audit_session_id=audit_session_id,
        user_id=user_id,
        limit=limit,
        skip=skip
    )

@router.get("/users/{user_id}",
    summary="Get chat history for a user",
    description="Retrieves chat history for a specific user with pagination and filtering options",
    response_model=List[ChatHistoryItem]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def read_user_history(
    user_id: str,
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session"),
    limit: Optional[int] = Query(100, ge=1, le=1000, description="Limit number of records"),
    skip: Optional[int] = Query(0, ge=0, description="Skip number of records for pagination"),
):
    return get_user_history(
        user_id=user_id,
        compliance_domain=compliance_domain,
        audit_session_id=audit_session_id,
        limit=limit,
        skip=skip
    )