from fastapi import HTTPException
from postgrest import APIError
from db.supabase_client import create_supabase_client
from config.config import settings

supabase = create_supabase_client()

def check_database_connection():
    """
    Run a minimal query against your 'documents' table to verify the DB is reachable.
    Returns the raw row data (list of dicts), or raises HTTPException on failure.
    """
    try:
        resp = (
            supabase
            .table(settings.supabase_table_documents)
            .select("id")
            .limit(1)
            .execute()
        )
        return resp.data

    except APIError as e:
        # Supabase‐py wraps PostgREST errors here
        raise HTTPException(
            status_code=getattr(e, "status_code", 500),
            detail=f"Supabase API error: {e}"
        )

    except Exception as e:
        # Fallback for any other errors
        raise HTTPException(status_code=500, detail=str(e))
