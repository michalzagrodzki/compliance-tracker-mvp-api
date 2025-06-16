import logging
from typing import List, Dict
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def get_history(conversation_id: str) -> List[Dict[str, str]]:
    resp = (
        supabase
        .table(settings.supabase_table_chat_history)
        .select("question, answer")
        .eq("conversation_id", conversation_id)
        .order("id", desc=False)
        .execute()
    )
    if hasattr(resp, "error") and resp.error:
        logger.error("Supabase 'get_history' failed", exc_info=True)
        raise HTTPException(status_code=500, detail=resp.error.message)
    return [
        {"question": r["question"], "answer": r["answer"]}
        for r in resp.data
    ]
