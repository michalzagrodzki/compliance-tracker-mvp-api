import logging
from typing import List, Dict, Any
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def list_documents(skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Fetch paginated documents from Supabase.
    Raises HTTPException on error.
    """
    try:
        logger.info(f"Fetching documents: skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_documents)
            .select("id, content, embedding, metadata")
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} documents")
        return resp.data
    except Exception as e:
        logger.error("Failed to fetch documents", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
