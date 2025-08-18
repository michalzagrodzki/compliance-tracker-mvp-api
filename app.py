import logging
from typing import Any, Dict
from fastapi import FastAPI, Request

from config.config import settings, tags_metadata
from config.cors import configure_cors
from security.input_validator import SecurityError
from services.db_check import check_database_connection
from auth.decorators import authorize

# Import routers
from api.auth import router as auth_router
from api.documents import router as documents_router
from api.rag import router as rag_router
from api.compliance import router as compliance_router
from api.audit_sessions import router as audit_sessions_router
from api.audit_reports import router as audit_reports_router
from api.audit_logs import router as audit_logs_router
from api.history import router as history_router
from api.ingestion import router as ingestion_router
from api.iso_controls import router as iso_controls_router
from api.users import router as users_router
from api.health import router as health_router
from api.executive_summary import router as executive_summary_router
from api.threat_intelligence import router as threat_intelligence_router
from api.risk_prioritization import router as risk_prioritization_router
from api.target_audience import router as target_audience_router

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

app = FastAPI(
    title="RAG FastAPI Supabase API",
    version="1.0.0",
    description="RAG service using Supabase vector store and OpenAI API",
    openapi_tags=tags_metadata,
)

configure_cors(app)


@app.exception_handler(SecurityError)
async def security_error_handler(request: Request, exc: SecurityError):
    return {"detail": str(exc), "type": "security_error"}




# Include all routers with v1 prefix
app.include_router(auth_router, prefix="/v1")
app.include_router(documents_router, prefix="/v1")
app.include_router(rag_router, prefix="/v1")
app.include_router(compliance_router, prefix="/v1")
app.include_router(audit_sessions_router, prefix="/v1")
app.include_router(audit_reports_router, prefix="/v1")
app.include_router(audit_logs_router, prefix="/v1")
app.include_router(history_router, prefix="/v1")
app.include_router(ingestion_router, prefix="/v1")
app.include_router(iso_controls_router, prefix="/v1")
app.include_router(users_router, prefix="/v1")
app.include_router(health_router, prefix="/v1")
app.include_router(executive_summary_router, prefix="/v1")
app.include_router(threat_intelligence_router, prefix="/v1")
app.include_router(risk_prioritization_router, prefix="/v1")
app.include_router(target_audience_router, prefix="/v1")


# Keep any utility functions that might be needed
def _build_query_metadata(
    sources: list[Dict[str, Any]], 
    compliance_domain: str | None, 
    document_version: str | None, 
    document_tags: list[str] | None
) -> Dict[str, Any]:
    """Build metadata dictionary from query sources and parameters."""
    return {
        "sources_count": len(sources),
        "compliance_domain": compliance_domain,
        "document_version": document_version,
        "document_tags": document_tags or [],
        "source_documents": [
            {"id": source.get("id"), "source_filename": source.get("source_filename")} 
            for source in sources
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)