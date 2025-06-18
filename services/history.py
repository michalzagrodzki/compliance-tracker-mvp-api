import logging
from typing import List, Dict, Optional
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def get_history(
    conversation_id: str,
    audit_session_id: Optional[str] = None,
    compliance_domain: Optional[str] = None,
    limit: int = 10
) -> List[Dict[str, str]]:
    try:
        logger.info(f"Fetching history for conversation {conversation_id}")
        
        query = (
            supabase
            .table(settings.supabase_table_chat_history)
            .select("question, answer, created_at")
            .eq("conversation_id", conversation_id)
            .order("created_at", desc=False)
            .limit(limit)
        )
        
        if audit_session_id:
            query = query.eq("audit_session_id", audit_session_id)
            
        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
        
        resp = query.execute()
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase history query failed", exc_info=True)
            raise HTTPException(status_code=500, detail=resp.error.message)
            
        history_items = [
            {"question": r["question"], "answer": r["answer"]}
            for r in resp.data
        ]
        
        logger.info(f"Retrieved {len(history_items)} history items for conversation {conversation_id}")
        return history_items
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get history for conversation {conversation_id}", exc_info=True)
        return []

