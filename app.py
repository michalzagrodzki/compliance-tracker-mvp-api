import logging
from typing import Any, Dict
from fastapi import FastAPI, Request

from config.config import settings, tags_metadata
from config.cors import configure_cors
from security.input_validator import SecurityError
from services.db_check import check_database_connection
from auth.decorators import authorize

# Enhanced error handling imports
from common.logging import setup_logging, get_logger
from common.middleware import setup_middleware
from common.exceptions import BaseRAGException
from common.responses import create_error_response

# Import routers
from api.auth import router as auth_router
from api.documents import router as documents_router
from api.rag import router as rag_router
from api.compliance_gaps import router as compliance_gaps_router
from api.compliance_domains import router as compliance_domains_router
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

# Setup enhanced logging
setup_logging(
    level="INFO",
    format_type="structured"
)

logger = get_logger("main")

app = FastAPI(
    title="RAG FastAPI Supabase API",
    version="1.0.0",
    description="RAG service using Supabase vector store and OpenAI API",
    openapi_tags=tags_metadata,
)

# Setup middleware (includes error handling)
setup_middleware(app)

configure_cors(app)

@app.get("/", 
    summary="Root endpoint", 
    description="Simple health check and API info"
)
async def root():
    """Root endpoint for basic health check."""
    return {
        "message": "RAG FastAPI Supabase API",
        "version": "1.0.0",
        "status": "healthy",
        "docs": "/docs",
        "redoc": "/redoc"
    }


@app.exception_handler(SecurityError)
async def security_error_handler(request: Request, exc: SecurityError):
    logger.warning(f"Security error: {exc}", extra={
        "path": str(request.url.path),
        "method": request.method,
        "client_ip": request.client.host if request.client else None
    })
    return create_error_response(
        error_code="SECURITY_ERROR",
        message=str(exc),
        status_code=400
    )


@app.exception_handler(BaseRAGException)
async def rag_exception_handler(request: Request, exc: BaseRAGException):
    logger.error(f"RAG exception: {exc.error_code}", extra={
        "error_code": exc.error_code,
        "context": exc.context,
        "path": str(request.url.path),
        "method": request.method
    })
    return create_error_response(
        error_code=exc.error_code,
        message=exc.detail,
        status_code=exc.status_code,
        context=exc.context
    )




# Include all routers with v1 prefix
app.include_router(auth_router, prefix="/v1")
app.include_router(documents_router, prefix="/v1")
app.include_router(rag_router, prefix="/v1")
app.include_router(compliance_gaps_router, prefix="/v1")
app.include_router(compliance_domains_router, prefix="/v1")
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