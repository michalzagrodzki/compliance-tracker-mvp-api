from pydantic import BaseModel, Field
from typing import Any, List, Dict, Optional
from datetime import datetime
from uuid import UUID

class UploadResponse(BaseModel):
    message: str
    inserted_count: int
    ingestion_id: str = Field(description="UUID of the ingestion record")
    compliance_domain: Optional[str] = Field(None, description="Compliance domain assigned to the document")
    document_version: Optional[str] = Field(None, description="Document version")

class QueryRequest(BaseModel):
    question: str
    conversation_id: Optional[str] = Field(None, description="Conversation UUID")
    compliance_domain: Optional[str] = Field(None, description="Filter results by compliance domain")
    match_threshold: Optional[float] = Field(0.75, description="Similarity threshold for document matching")
    match_count: Optional[int] = Field(5, description="Maximum number of documents to retrieve")

class SourceDoc(BaseModel):
    page_content: str | None = None
    metadata: Dict[str, Any]
    similarity: float | None = None
    id: str

class QueryResponse(BaseModel):
    answer: str
    source_docs: List[SourceDoc]
    compliance_domain_filter: Optional[str] = Field(None, description="Applied compliance domain filter")

class ChatHistoryItem(BaseModel):
    id: int
    conversation_id: str
    question: str
    answer: str

class IngestionStatus(BaseModel):
    id: str
    filename: str
    compliance_domain: Optional[str]
    document_version: Optional[str]
    processing_status: str
    total_chunks: Optional[int]
    ingested_at: str
    error_message: Optional[str]

class DocumentListItem(BaseModel):
    id: str
    filename: str
    compliance_domain: Optional[str]
    document_version: Optional[str]
    file_size: Optional[int]
    total_chunks: Optional[int]
    ingested_at: str
    processing_status: str

class ComplianceDomain(BaseModel):
    code: str = Field(..., description="Unique domain code (e.g., 'GDPR', 'ISO27001')")
    name: str = Field(..., description="Human-readable domain name")
    description: Optional[str] = Field(None, description="Detailed description of the compliance domain")
    is_active: bool = Field(True, description="Whether the domain is currently active")
    created_at: datetime = Field(..., description="When the domain was created")

class ComplianceDomainsResponse(BaseModel):
    domains: List[ComplianceDomain]
    total: int = Field(..., description="Total number of domains (for pagination)")
    page: int = Field(..., description="Current page number")
    limit: int = Field(..., description="Items per page")

class AuditSessionBase(BaseModel):
    session_name: str = Field(..., description="Name of the audit session")
    compliance_domain: str = Field(..., description="Compliance domain (e.g., GDPR, ISO27001)")

class AuditSessionCreate(AuditSessionBase):
    user_id: str = Field(..., description="ID of the user creating the session")
    ip_address: Optional[str] = Field(None, description="Client IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")

class AuditSessionUpdate(BaseModel):
    ended_at: Optional[datetime] = Field(None, description="Session end time")
    session_summary: Optional[str] = Field(None, description="Summary of the audit session")
    is_active: Optional[bool] = Field(None, description="Whether the session is active")
    total_queries: Optional[int] = Field(None, description="Total number of queries in the session")

class AuditSessionResponse(AuditSessionBase):
    id: UUID = Field(..., description="Unique session identifier")
    user_id: UUID = Field(..., description="ID of the user who created the session")
    started_at: datetime = Field(..., description="Session start time")
    ended_at: Optional[datetime] = Field(None, description="Session end time")
    total_queries: int = Field(default=0, description="Total number of queries")
    session_summary: Optional[str] = Field(None, description="Summary of the session")
    is_active: bool = Field(default=True, description="Whether the session is active")
    ip_address: Optional[str] = Field(None, description="Client IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")

    class Config:
        from_attributes = True

class AuditSessionSearchRequest(BaseModel):
    compliance_domain: Optional[str] = Field(None, description="Filter by compliance domain")
    user_id: Optional[str] = Field(None, description="Filter by user ID")
    started_at: Optional[datetime] = Field(None, description="Filter sessions started after this date")
    ended_at: Optional[datetime] = Field(None, description="Filter sessions ended before this date")
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    skip: int = Field(0, ge=0, description="Number of records to skip")
    limit: int = Field(10, ge=1, le=100, description="Maximum number of records to return")