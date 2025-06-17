import logging
from typing import List, Dict, Any
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def list_compliance_domains(skip: int = 0, limit: int = 10, is_active: bool = True) -> List[Dict[str, Any]]:
    """
    Fetch paginated compliance domains from Supabase.
    Raises HTTPException on error.
    """
    try:
        logger.info(f"Fetching compliance domains: skip={skip}, limit={limit}, is_active={is_active}")
        
        query = (
            supabase
            .table(settings.supabase_table_compliance_domains)
            .select("code, name, description, is_active, created_at")
            .limit(limit)
            .offset(skip)
            .order("name")
        )
        
        # Filter by is_active if specified
        if is_active is not None:
            query = query.eq("is_active", is_active)
            
        resp = query.execute()
        
        logger.info(f"Received {len(resp.data)} compliance domains")
        return resp.data
    except Exception as e:
        logger.error("Failed to fetch compliance domains", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_compliance_domain_by_code(code: str) -> Dict[str, Any]:
    """
    Fetch a single compliance domain by code.
    Raises HTTPException on error or if not found.
    """
    try:
        logger.info(f"Fetching compliance domain with code: {code}")
        resp = (
            supabase
            .table(settings.supabase_table_compliance_domains)
            .select("code, name, description, is_active, created_at")
            .eq("code", code)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Compliance domain with code '{code}' not found")
        
        logger.info(f"Found compliance domain: {code}")
        return resp.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch compliance domain {code}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")