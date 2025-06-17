from pydantic import BaseModel, Field
from typing import Any, List, Dict, Optional
from datetime import datetime

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