from fastapi import APIRouter

from auth.decorators import authorize
from services.db_check import check_database_connection

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("/db",
    summary="Database connectivity check",
    description="Check if the application can connect to the database"
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def test_db():
    data = check_database_connection()
    return {"status": "ok", "result": data}


@router.get("/status",
    summary="Application health status",
    description="Basic health check endpoint"
)
def health_status():
    return {"status": "healthy", "service": "RAG FastAPI Supabase API", "version": "1.0.0"}