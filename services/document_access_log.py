import logging
from typing import List, Dict, Any, Optional
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def list_document_access_logs(skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching document access logs: skip={skip}, limit={limit}")
        resp = (
            supabase
            .table("document_access_log")
            .select("id, user_id, document_id, access_type, audit_session_id, accessed_at, query_text, ip_address, user_agent")
            .order("accessed_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} document access log entries")
        return resp.data
    except Exception as e:
        logger.error("Failed to fetch document access logs", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_document_access_log_by_id(log_id: str) -> Dict[str, Any]:
    try:
        logger.info(f"Fetching document access log by ID: {log_id}")
        resp = (
            supabase
            .table("document_access_log")
            .select("id, user_id, document_id, access_type, audit_session_id, accessed_at, query_text, ip_address, user_agent")
            .eq("id", log_id)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Document access log with ID {log_id} not found")
        
        logger.info(f"Found document access log entry: {log_id}")
        return resp.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch document access log by ID {log_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_document_access_logs_by_user(user_id: str, skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching document access logs for user: {user_id}, skip={skip}, limit={limit}")
        resp = (
            supabase
            .table("document_access_log")
            .select("id, user_id, document_id, access_type, audit_session_id, accessed_at, query_text, ip_address, user_agent")
            .eq("user_id", user_id)
            .order("accessed_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} document access log entries for user {user_id}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch document access logs for user {user_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_document_access_logs_by_document(document_id: str, skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching document access logs for document: {document_id}, skip={skip}, limit={limit}")
        resp = (
            supabase
            .table("document_access_log")
            .select("id, user_id, document_id, access_type, audit_session_id, accessed_at, query_text, ip_address, user_agent")
            .eq("document_id", document_id)
            .order("accessed_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} document access log entries for document {document_id}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch document access logs for document {document_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_document_access_logs_by_audit_session(audit_session_id: str, skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching document access logs for audit session: {audit_session_id}, skip={skip}, limit={limit}")
        resp = (
            supabase
            .table("document_access_log")
            .select("id, user_id, document_id, access_type, audit_session_id, accessed_at, query_text, ip_address, user_agent")
            .eq("audit_session_id", audit_session_id)
            .order("accessed_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} document access log entries for audit session {audit_session_id}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch document access logs for audit session {audit_session_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_document_access_logs_filtered(
    user_id: Optional[str] = None,
    document_id: Optional[str] = None,
    access_type: Optional[str] = None,
    audit_session_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 10
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching filtered document access logs: user_id={user_id}, document_id={document_id}, access_type={access_type}, audit_session_id={audit_session_id}, skip={skip}, limit={limit}")
        
        query = (
            supabase
            .table("document_access_log")
            .select("id, user_id, document_id, access_type, audit_session_id, accessed_at, query_text, ip_address, user_agent")
        )

        if user_id:
            query = query.eq("user_id", user_id)
        if document_id:
            query = query.eq("document_id", document_id)
        if access_type:
            query = query.eq("access_type", access_type)
        if audit_session_id:
            query = query.eq("audit_session_id", audit_session_id)
        
        resp = (
            query
            .order("accessed_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        logger.info(f"Received {len(resp.data)} filtered document access log entries")
        return resp.data
    except Exception as e:
        logger.error("Failed to fetch filtered document access logs", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")