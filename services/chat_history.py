import logging
from typing import List, Dict
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def get_chat_history(conversation_id: str) -> List[Dict[str, str]]:
    """
    Fetch all chat turns for a given conversation_id.
    Returns a list of dicts with keys: id (str), conversation_id, question, answer.
    Raises HTTPException on any error.
    """
    try:
        logger.info(f"Fetching history for conversation {conversation_id}")
        resp = (
            supabase
            .table(settings.supabase_table_chat_history)
            .select("id, conversation_id, question, answer")
            .eq("conversation_id", conversation_id)
            .execute()
        )
        rows = resp.data or []
        data: List[Dict[str, str]] = []
        for row in rows:
            # ensure id is serialized as string
            row["id"] = str(row["id"])
            data.append(row)
        logger.info(f"Received {len(data)} chat history entries")
        return data

    except Exception as e:
        logger.error("Error fetching chat history", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
