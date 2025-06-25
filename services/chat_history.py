import logging
from typing import Any, List, Dict, Optional
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def get_chat_history(
    conversation_id: str,
    audit_session_id: Optional[str] = None,
    compliance_domain: Optional[str] = None,
    user_id: Optional[str] = None,
    limit: Optional[int] = None
) -> List[Dict[str, any]]:
    try:
        logger.info(f"Fetching history for conversation {conversation_id}")

        query = (
            supabase
            .table(settings.supabase_table_chat_history)
            .select("""
                id,
                conversation_id,
                question,
                answer,
                created_at,
                audit_session_id,
                compliance_domain,
                source_document_ids,
                match_threshold,
                match_count,
                user_id,
                response_time_ms,
                total_tokens_used,
                metadata
            """)
            .eq("conversation_id", conversation_id)
            .order("created_at", desc=False)
        )
        
        if audit_session_id:
            query = query.eq("audit_session_id", audit_session_id)
            
        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
            
        if user_id:
            query = query.eq("user_id", user_id)
            
        if limit:
            query = query.limit(limit)
        
        resp = query.execute()
        rows = resp.data or []

        data: List[Dict[str, any]] = []
        for row in rows:
            processed_row = {
                "id": str(row["id"]),
                "conversation_id": str(row["conversation_id"]),
                "question": row["question"],
                "answer": row["answer"],
                "created_at": row["created_at"],
                "audit_session_id": str(row["audit_session_id"]) if row["audit_session_id"] else None,
                "compliance_domain": row["compliance_domain"],
                "source_document_ids": [str(doc_id) for doc_id in (row["source_document_ids"] or [])],
                "match_threshold": float(row["match_threshold"]) if row["match_threshold"] else None,
                "match_count": row["match_count"],
                "user_id": str(row["user_id"]) if row["user_id"] else None,
                "response_time_ms": row["response_time_ms"],
                "total_tokens_used": row["total_tokens_used"],
                "metadata": row.get("metadata", {})
            }
            data.append(processed_row)
        
        logger.info(f"Received {len(data)} chat history entries")
        return data
        
    except Exception as e:
        logger.error("Error fetching chat history", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


def insert_chat_history(
    conversation_id: str,
    question: str,
    answer: str,
    audit_session_id: Optional[str] = None,
    compliance_domain: Optional[str] = None,
    source_document_ids: Optional[List[str]] = None,
    match_threshold: Optional[float] = None,
    match_count: Optional[int] = None,
    user_id: Optional[str] = None,
    response_time_ms: Optional[int] = None,
    total_tokens_used: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, any]:
    try:
        insert_data = {
            "conversation_id": conversation_id,
            "question": question,
            "answer": answer,
            "audit_session_id": audit_session_id,
            "compliance_domain": compliance_domain,
            "source_document_ids": source_document_ids or [],
            "match_threshold": match_threshold,
            "match_count": match_count,
            "user_id": user_id,
            "response_time_ms": response_time_ms,
            "total_tokens_used": total_tokens_used,
            "metadata": metadata or {}
        }
        
        insert_data = {k: v for k, v in insert_data.items() if v is not None}
        
        resp = (
            supabase
            .table(settings.supabase_table_chat_history)
            .insert(insert_data)
            .execute()
        )
        
        if resp.data:
            logger.info(f"Inserted chat history record for conversation {conversation_id}")
            return resp.data[0]
        else:
            raise HTTPException(status_code=500, detail="Failed to insert chat history")
            
    except Exception as e:
        logger.error("Error inserting chat history", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


def get_audit_session_history(
    audit_session_id: str,
    compliance_domain: Optional[str] = None
) -> List[Dict[str, any]]:
    try:
        logger.info(f"Fetching audit session history for {audit_session_id}")
        
        query = (
            supabase
            .table(settings.supabase_table_chat_history)
            .select("""
                id,
                conversation_id,
                question,
                answer,
                created_at,
                compliance_domain,
                source_document_ids,
                match_threshold,
                match_count,
                user_id,
                response_time_ms,
                total_tokens_used,
                metadata
            """)
            .eq("audit_session_id", audit_session_id)
            .order("created_at", desc=False)
        )
        
        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
            
        resp = query.execute()
        rows = resp.data or []
        
        # Process similar to get_chat_history
        data: List[Dict[str, any]] = []
        for row in rows:
            processed_row = {
                "id": str(row["id"]),
                "conversation_id": str(row["conversation_id"]),
                "question": row["question"],
                "answer": row["answer"],
                "created_at": row["created_at"],
                "compliance_domain": row["compliance_domain"],
                "source_document_ids": [str(doc_id) for doc_id in (row["source_document_ids"] or [])],
                "match_threshold": float(row["match_threshold"]) if row["match_threshold"] else None,
                "match_count": row["match_count"],
                "user_id": str(row["user_id"]) if row["user_id"] else None,
                "response_time_ms": row["response_time_ms"],
                "total_tokens_used": row["total_tokens_used"],
                "metadata": row.get("metadata", {})
            }
            data.append(processed_row)
            
        logger.info(f"Received {len(data)} audit session entries")
        return data
        
    except Exception as e:
        logger.error("Error fetching audit session history", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_audit_session_history(
    audit_session_id: str,
    compliance_domain: Optional[str] = None
) -> List[Dict[str, any]]:
    try:
        logger.info(f"Fetching audit session history for {audit_session_id}")
        
        query = (
            supabase
            .table(settings.supabase_table_chat_history)
            .select("""
                id,
                conversation_id,
                question,
                answer,
                created_at,
                compliance_domain,
                source_document_ids,
                match_threshold,
                match_count,
                user_id,
                response_time_ms,
                total_tokens_used,
                metadata
            """)
            .eq("audit_session_id", audit_session_id)
            .order("created_at", desc=False)
        )
        
        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
            
        resp = query.execute()
        rows = resp.data or []
        
        # Process similar to get_chat_history
        data: List[Dict[str, any]] = []
        for row in rows:
            processed_row = {
                "id": str(row["id"]),
                "conversation_id": str(row["conversation_id"]),
                "question": row["question"],
                "answer": row["answer"],
                "created_at": row["created_at"],
                "compliance_domain": row["compliance_domain"],
                "source_document_ids": [str(doc_id) for doc_id in (row["source_document_ids"] or [])],
                "match_threshold": float(row["match_threshold"]) if row["match_threshold"] else None,
                "match_count": row["match_count"],
                "user_id": str(row["user_id"]) if row["user_id"] else None,
                "response_time_ms": row["response_time_ms"],
                "total_tokens_used": row["total_tokens_used"],
                "metadata": row.get("metadata", {})
            }
            data.append(processed_row)
            
        logger.info(f"Received {len(data)} audit session entries")
        return data
        
    except Exception as e:
        logger.error("Error fetching audit session history", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


def get_domain_history(
    domain_code: str,
    audit_session_id: Optional[str] = None,
    user_id: Optional[str] = None,
    limit: int = 100,
    skip: int = 0
) -> List[Dict[str, any]]:
    try:
        logger.info(f"Fetching domain history for {domain_code}")
        
        query = (
            supabase
            .table(settings.supabase_table_chat_history)
            .select("""
                id, conversation_id, question, answer, created_at,
                audit_session_id, compliance_domain, source_document_ids,
                match_threshold, match_count, user_id, response_time_ms, total_tokens_used, metadata
            """)
            .eq("compliance_domain", domain_code)
            .order("created_at", desc=True)
            .limit(limit)
            .offset(skip)
        )
        
        if audit_session_id:
            query = query.eq("audit_session_id", audit_session_id)
        if user_id:
            query = query.eq("user_id", user_id)
            
        resp = query.execute()
        rows = resp.data or []
        
        # Process the data
        data: List[Dict[str, any]] = []
        for row in rows:
            processed_row = {
                "id": str(row["id"]),
                "conversation_id": str(row["conversation_id"]),
                "question": row["question"],
                "answer": row["answer"],
                "created_at": row["created_at"],
                "audit_session_id": str(row["audit_session_id"]) if row["audit_session_id"] else None,
                "compliance_domain": row["compliance_domain"],
                "source_document_ids": [str(doc_id) for doc_id in (row["source_document_ids"] or [])],
                "match_threshold": float(row["match_threshold"]) if row["match_threshold"] else None,
                "match_count": row["match_count"],
                "user_id": str(row["user_id"]) if row["user_id"] else None,
                "response_time_ms": row["response_time_ms"],
                "total_tokens_used": row["total_tokens_used"],
                "metadata": row.get("metadata", {})
            }
            data.append(processed_row)
            
        logger.info(f"Received {len(data)} domain history entries for {domain_code}")
        return data
        
    except Exception as e:
        logger.error(f"Error fetching domain history for {domain_code}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


def get_user_history(
    user_id: str,
    compliance_domain: Optional[str] = None,
    audit_session_id: Optional[str] = None,
    limit: int = 100,
    skip: int = 0
) -> List[Dict[str, any]]:
    try:
        logger.info(f"Fetching user history for {user_id}")
        
        query = (
            supabase
            .table(settings.supabase_table_chat_history)
            .select("""
                id, conversation_id, question, answer, created_at,
                audit_session_id, compliance_domain, source_document_ids,
                match_threshold, match_count, user_id, response_time_ms, total_tokens_used, metadata
            """)
            .eq("user_id", user_id)
            .order("created_at", desc=True)
            .limit(limit)
            .offset(skip)
        )
        
        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
        if audit_session_id:
            query = query.eq("audit_session_id", audit_session_id)
            
        resp = query.execute()
        rows = resp.data or []
        
        # Process the data
        data: List[Dict[str, any]] = []
        for row in rows:
            processed_row = {
                "id": str(row["id"]),
                "conversation_id": str(row["conversation_id"]),
                "question": row["question"],
                "answer": row["answer"],
                "created_at": row["created_at"],
                "audit_session_id": str(row["audit_session_id"]) if row["audit_session_id"] else None,
                "compliance_domain": row["compliance_domain"],
                "source_document_ids": [str(doc_id) for doc_id in (row["source_document_ids"] or [])],
                "match_threshold": float(row["match_threshold"]) if row["match_threshold"] else None,
                "match_count": row["match_count"],
                "user_id": str(row["user_id"]) if row["user_id"] else None,
                "response_time_ms": row["response_time_ms"],
                "total_tokens_used": row["total_tokens_used"],
                "metadata": row.get("metadata", {})
            }
            data.append(processed_row)
            
        logger.info(f"Received {len(data)} user history entries for {user_id}")
        return data
        
    except Exception as e:
        logger.error(f"Error fetching user history for {user_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
