from pydantic import BaseModel, Field, validator
from typing import Any, List, Dict, Literal, Optional, Union
from datetime import datetime
from uuid import UUID
from decimal import Decimal

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
    """Enhanced chat history item matching the new table schema"""
    id: str
    conversation_id: str
    question: str
    answer: str
    created_at: datetime
    
    # Audit and compliance tracking
    audit_session_id: Optional[str] = None
    compliance_domain: Optional[str] = None
    source_document_ids: List[str] = Field(default_factory=list)
    match_threshold: Optional[float] = None
    match_count: Optional[int] = None
    user_id: Optional[str] = None
    
    # Query performance metrics
    response_time_ms: Optional[int] = None
    total_tokens_used: Optional[int] = None

class ChatHistoryFilters(BaseModel):
    """Query parameters for filtering chat history"""
    audit_session_id: Optional[str] = Field(None, description="Filter by audit session UUID")
    compliance_domain: Optional[str] = Field(None, description="Filter by compliance domain code")
    user_id: Optional[str] = Field(None, description="Filter by user UUID")
    limit: Optional[int] = Field(None, ge=1, le=1000, description="Limit number of records returned")

class AuditSessionSummary(BaseModel):
    """Summary statistics for an audit session"""
    audit_session_id: str
    total_queries: int
    compliance_domains: List[str]
    total_response_time_ms: Optional[int] = None
    total_tokens_used: Optional[int] = None
    unique_conversations: int
    created_at_range: Dict[str, datetime]  # {"start": datetime, "end": datetime}

class ComplianceDomainStats(BaseModel):
    """Statistics for a specific compliance domain"""
    domain_code: str
    total_queries: int
    avg_response_time_ms: Optional[float] = None
    avg_tokens_per_query: Optional[float] = None
    unique_users: int
    most_recent_query: Optional[datetime] = None

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

class DocumentAccessLogItem(BaseModel):
    id: UUID
    user_id: UUID | None = None
    document_id: UUID | None = None
    access_type: str 
    audit_session_id: UUID | None = None
    accessed_at: datetime
    query_text: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None

class CreateDocumentAccessLog(BaseModel):
    user_id: UUID | None = None
    document_id: UUID | None = None
    access_type: str = Field(..., pattern="^(view|search|download|reference)$")
    audit_session_id: UUID | None = None
    query_text: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None

class ComplianceGapBase(BaseModel):
    user_id: UUID = Field(..., description="ID of the user who identified the gap")
    audit_session_id: UUID = Field(..., description="Audit session where gap was identified")
    compliance_domain: str = Field(..., description="Compliance domain code (e.g., GDPR, ISO27001)")
    gap_type: str = Field(..., description="Type of gap identified")
    gap_category: str = Field(..., description="Specific category within the compliance domain")
    gap_title: str = Field(..., max_length=255, description="Human-readable title for the gap")
    gap_description: str = Field(..., description="Detailed description of the gap")
    original_question: str = Field(..., description="The question that revealed this gap")
    
    @validator('gap_type')
    def validate_gap_type(cls, v):
        valid_types = ['missing_policy', 'outdated_policy', 'low_confidence', 'conflicting_policies', 'incomplete_coverage', 'no_evidence']
        if v not in valid_types:
            raise ValueError(f'gap_type must be one of: {", ".join(valid_types)}')
        return v

class ComplianceGapCreate(ComplianceGapBase):
    """Request to create a compliance gap directly"""
    creation_method: Literal["direct"] = Field("direct", description="Method of creation")
    chat_history_id: Optional[int] = Field(None, description="Related chat history record")
    pdf_ingestion_id: Optional[UUID] = Field(None, description="Document that should have contained the info")
    expected_answer_type: Optional[str] = Field(None, max_length=100, description="Expected type of answer")
    search_terms_used: Optional[List[str]] = Field(None, description="Keywords searched")
    similarity_threshold_used: Optional[Decimal] = Field(None, ge=0, le=1, description="Search threshold used")
    best_match_score: Optional[Decimal] = Field(None, ge=0, le=1, description="Best similarity score found")
    
    risk_level: str = Field("medium", description="Risk level assessment")
    business_impact: str = Field("medium", description="Business impact assessment")
    regulatory_requirement: bool = Field(False, description="Is this a regulatory requirement?")
    potential_fine_amount: Optional[Decimal] = Field(None, ge=0, description="Potential fine amount")
    
    recommendation_type: Optional[str] = Field(None, description="Type of recommendation")
    recommendation_text: Optional[str] = Field(None, description="Recommendation details")
    recommended_actions: Optional[List[str]] = Field(default_factory=list, description="Specific actions")
    related_documents: Optional[List[str]] = Field(default_factory=list, description="Related documents")
    
    detection_method: str = Field("query_analysis", description="How the gap was detected")
    confidence_score: Optional[Decimal] = Field(0.80, ge=0, le=1, description="Detection confidence")
    false_positive_likelihood: Optional[Decimal] = Field(0.20, ge=0, le=1, description="False positive probability")
    
    ip_address: Optional[str] = Field(None, description="Client IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    session_context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional context")
    
    @validator('risk_level', 'business_impact')
    def validate_risk_levels(cls, v):
        valid_levels = ['low', 'medium', 'high', 'critical']
        if v not in valid_levels:
            raise ValueError(f'must be one of: {", ".join(valid_levels)}')
        return v
    
    @validator('detection_method')
    def validate_detection_method(cls, v):
        valid_methods = ['query_analysis', 'periodic_scan', 'document_upload', 'manual_review', 'external_audit']
        if v not in valid_methods:
            raise ValueError(f'detection_method must be one of: {", ".join(valid_methods)}')
        return v
    
    @validator('recommendation_type')
    def validate_recommendation_type(cls, v):
        if v is None:
            return v
        valid_types = ['create_policy', 'update_policy', 'upload_document', 'training_needed', 'process_improvement', 'system_configuration']
        if v not in valid_types:
            raise ValueError(f'recommendation_type must be one of: {", ".join(valid_types)}')
        return v

class ComplianceGapUpdate(BaseModel):
    gap_title: Optional[str] = Field(None, max_length=255)
    gap_description: Optional[str] = None
    risk_level: Optional[str] = None
    business_impact: Optional[str] = None
    regulatory_requirement: Optional[bool] = None
    potential_fine_amount: Optional[Decimal] = Field(None, ge=0)
    assigned_to: Optional[UUID] = None
    due_date: Optional[datetime] = None
    resolution_notes: Optional[str] = None
    recommendation_type: Optional[str] = None
    recommendation_text: Optional[str] = None
    recommended_actions: Optional[List[str]] = None
    related_documents: Optional[List[str]] = None
    confidence_score: Optional[Decimal] = Field(None, ge=0, le=1)
    false_positive_likelihood: Optional[Decimal] = Field(None, ge=0, le=1)
    session_context: Optional[Dict[str, Any]] = None
    
    @validator('risk_level', 'business_impact')
    def validate_risk_levels(cls, v):
        if v is None:
            return v
        valid_levels = ['low', 'medium', 'high', 'critical']
        if v not in valid_levels:
            raise ValueError(f'must be one of: {", ".join(valid_levels)}')
        return v

class ComplianceGapStatusUpdate(BaseModel):
    status: str = Field(..., description="New status for the gap")
    resolution_notes: Optional[str] = Field(None, description="Notes about the status change")
    
    @validator('status')
    def validate_status(cls, v):
        valid_statuses = ['identified', 'acknowledged', 'in_progress', 'resolved', 'false_positive', 'accepted_risk']
        if v not in valid_statuses:
            raise ValueError(f'status must be one of: {", ".join(valid_statuses)}')
        return v

class ComplianceGapResponse(ComplianceGapBase):
    """Response model for a compliance gap record"""
    id: UUID = Field(..., description="Unique identifier for the gap")
    status: str = Field(..., description="Current status of the gap")
    
    # All fields from ComplianceGapCreate that might be returned
    chat_history_id: Optional[int] = None
    pdf_ingestion_id: Optional[UUID] = None
    expected_answer_type: Optional[str] = None
    search_terms_used: Optional[List[str]] = None
    similarity_threshold_used: Optional[Decimal] = None
    best_match_score: Optional[Decimal] = None
    
    risk_level: str
    business_impact: str
    regulatory_requirement: bool
    potential_fine_amount: Optional[Decimal] = None
    
    assigned_to: Optional[UUID] = None
    due_date: Optional[datetime] = None
    resolution_notes: Optional[str] = None
    
    recommendation_type: Optional[str] = None
    recommendation_text: Optional[str] = None
    recommended_actions: List[str] = Field(default_factory=list)
    related_documents: List[str] = Field(default_factory=list)
    
    detection_method: str
    confidence_score: Decimal
    auto_generated: bool = True
    false_positive_likelihood: Decimal
    
    # Timestamps
    detected_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    last_reviewed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    
    # Additional context
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_context: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        from_attributes = True

class ComplianceGapAssignRequest(BaseModel):
    """Request to assign a compliance gap to a user"""
    assigned_to: UUID = Field(..., description="User ID to assign the gap to")
    due_date: Optional[datetime] = Field(None, description="Due date for resolution")

class ComplianceGapReviewRequest(BaseModel):
    """Request to mark a compliance gap as reviewed"""
    reviewer_notes: Optional[str] = Field(None, description="Notes from the reviewer")

class ComplianceGapStatisticsResponse(BaseModel):
    """Response model for compliance gaps statistics"""
    total_gaps: int = Field(..., description="Total number of gaps")
    regulatory_gaps: int = Field(..., description="Number of regulatory requirement gaps")
    total_potential_fines: Decimal = Field(..., description="Sum of potential fines")
    avg_confidence_score: Decimal = Field(..., description="Average confidence score")
    resolution_rate_percent: Decimal = Field(..., description="Percentage of resolved gaps")
    
    status_breakdown: Dict[str, int] = Field(..., description="Counts by status")
    risk_level_breakdown: Dict[str, int] = Field(..., description="Counts by risk level")
    domain_breakdown: Dict[str, int] = Field(..., description="Counts by compliance domain")
    gap_type_breakdown: Dict[str, int] = Field(..., description="Counts by gap type")
    
    filters_applied: Dict[str, Any] = Field(..., description="Filters used for these statistics")

class ComplianceGapFilterRequest(BaseModel):
    """Request model for filtering compliance gaps"""
    compliance_domain: Optional[str] = Field(None, description="Filter by compliance domain")
    gap_type: Optional[str] = Field(None, description="Filter by gap type")
    risk_level: Optional[str] = Field(None, description="Filter by risk level")
    status: Optional[str] = Field(None, description="Filter by status")
    assigned_to: Optional[UUID] = Field(None, description="Filter by assigned user")
    user_id: Optional[UUID] = Field(None, description="Filter by creator user")
    audit_session_id: Optional[UUID] = Field(None, description="Filter by audit session")
    detection_method: Optional[str] = Field(None, description="Filter by detection method")
    regulatory_requirement: Optional[bool] = Field(None, description="Filter by regulatory requirement")
    created_after: Optional[datetime] = Field(None, description="Filter by creation date (after)")
    created_before: Optional[datetime] = Field(None, description="Filter by creation date (before)")
    skip: int = Field(0, ge=0, description="Number of records to skip")
    limit: int = Field(10, ge=1, le=100, description="Maximum number of records to return")
    
    @validator('gap_type')
    def validate_gap_type(cls, v):
        if v is None:
            return v
        valid_types = ['missing_policy', 'outdated_policy', 'low_confidence', 'conflicting_policies', 'incomplete_coverage', 'no_evidence']
        if v not in valid_types:
            raise ValueError(f'gap_type must be one of: {", ".join(valid_types)}')
        return v
    
    @validator('risk_level')
    def validate_risk_level(cls, v):
        if v is None:
            return v
        valid_levels = ['low', 'medium', 'high', 'critical']
        if v not in valid_levels:
            raise ValueError(f'risk_level must be one of: {", ".join(valid_levels)}')
        return v
    
    @validator('status')
    def validate_status(cls, v):
        if v is None:
            return v
        valid_statuses = ['identified', 'acknowledged', 'in_progress', 'resolved', 'false_positive', 'accepted_risk']
        if v not in valid_statuses:
            raise ValueError(f'status must be one of: {", ".join(valid_statuses)}')
        return v
    
    @validator('detection_method')
    def validate_detection_method(cls, v):
        if v is None:
            return v
        valid_methods = ['query_analysis', 'periodic_scan', 'document_upload', 'manual_review', 'external_audit']
        if v not in valid_methods:
            raise ValueError(f'detection_method must be one of: {", ".join(valid_methods)}')
        return v

class ComplianceGapQueryAnalysisRequest(BaseModel):
    """Request to analyze a query for potential compliance gaps"""
    question: str = Field(..., description="The question to analyze")
    audit_session_id: UUID = Field(..., description="Audit session ID")
    compliance_domain: str = Field(..., description="Compliance domain code")
    match_threshold: float = Field(0.75, description="Similarity threshold for matching")
    match_count: int = Field(5, description="Number of matches to return")
    chat_history_id: Optional[int] = Field(None, description="Related chat history ID")

class ComplianceGapBulkActionRequest(BaseModel):
    """Request for bulk actions on multiple compliance gaps"""
    gap_ids: List[UUID] = Field(..., description="List of gap IDs to act on")
    action: str = Field(..., description="Action to perform on all gaps")
    
    # Depending on the action, one of these fields will be used
    status: Optional[str] = Field(None, description="New status to set")
    assigned_to: Optional[UUID] = Field(None, description="User to assign gaps to")
    due_date: Optional[datetime] = Field(None, description="Due date for resolution")
    notes: Optional[str] = Field(None, description="Notes to add to the gaps")
    
    @validator('action')
    def validate_action(cls, v):
        valid_actions = ['update_status', 'assign', 'set_due_date', 'add_notes']
        if v not in valid_actions:
            raise ValueError(f'action must be one of: {", ".join(valid_actions)}')
        return v
    
    @validator('status')
    def validate_status(cls, v, values):
        if values.get('action') == 'update_status' and v is None:
            raise ValueError('status is required when action is update_status')
        if v is not None:
            valid_statuses = ['identified', 'acknowledged', 'in_progress', 'resolved', 'false_positive', 'accepted_risk']
            if v not in valid_statuses:
                raise ValueError(f'status must be one of: {", ".join(valid_statuses)}')
        return v
    
    @validator('assigned_to')
    def validate_assigned_to(cls, v, values):
        if values.get('action') == 'assign' and v is None:
            raise ValueError('assigned_to is required when action is assign')
        return v
    
    @validator('due_date')
    def validate_due_date(cls, v, values):
        if values.get('action') == 'set_due_date' and v is None:
            raise ValueError('due_date is required when action is set_due_date')
        return v
    
    @validator('notes')
    def validate_notes(cls, v, values):
        if values.get('action') == 'add_notes' and v is None:
            raise ValueError('notes is required when action is add_notes')
        return v

class ComplianceGapExportRequest(BaseModel):
    """Request to export compliance gaps data"""
    format: str = Field(..., description="Export format")
    gap_ids: Optional[List[UUID]] = Field(None, description="Specific gap IDs to export")
    filters: Optional[ComplianceGapFilterRequest] = Field(None, description="Filters to apply")
    include_metadata: bool = Field(True, description="Include additional metadata")
    include_history: bool = Field(False, description="Include status history")
    
    @validator('format')
    def validate_format(cls, v):
        valid_formats = ['csv', 'json', 'pdf', 'xlsx']
        if v not in valid_formats:
            raise ValueError(f'format must be one of: {", ".join(valid_formats)}')
        return v

class ComplianceGapFromChatHistoryRequest(BaseModel):
    creation_method: Literal["from_chat_history"] = Field("from_chat_history", description="Method of creation")
    chat_history_id: str = Field(..., description="ID of the chat history entry to use as source")
    
    gap_type: str = Field(..., description="Type of gap identified")
    gap_category: str = Field(..., description="Specific category within the compliance domain")
    gap_title: str = Field(..., max_length=255, description="Human-readable title for the gap")
    gap_description: str = Field(..., description="Detailed description of the gap")
    
    audit_session_id: Optional[UUID] = Field(None, description="Override the audit session ID")
    compliance_domain: Optional[str] = Field(None, description="Override the compliance domain")
    search_terms_used: Optional[List[str]] = Field(None, description="Keywords searched")
    
    risk_level: str = Field("medium", description="Risk level assessment")
    business_impact: str = Field("medium", description="Business impact assessment")
    regulatory_requirement: bool = Field(False, description="Is this a regulatory requirement?")
    potential_fine_amount: Optional[Decimal] = Field(None, ge=0, description="Potential fine amount")
    
    recommendation_type: Optional[str] = Field(None, description="Type of recommendation")
    recommendation_text: Optional[str] = Field(None, description="Recommendation details")
    recommended_actions: Optional[List[str]] = Field(default_factory=list, description="Specific actions")
    related_documents: Optional[List[str]] = Field(default_factory=list, description="Related documents")
    
    confidence_score: Decimal = Field(0.90, ge=0, le=1, description="Confidence in this gap")
    false_positive_likelihood: Decimal = Field(0.10, ge=0, le=1, description="False positive probability")
    
    @validator('gap_type')
    def validate_gap_type(cls, v):
        valid_types = ['missing_policy', 'outdated_policy', 'low_confidence', 'conflicting_policies', 'incomplete_coverage', 'no_evidence']
        if v not in valid_types:
            raise ValueError(f'gap_type must be one of: {", ".join(valid_types)}')
        return v
    
    @validator('risk_level', 'business_impact')
    def validate_risk_levels(cls, v):
        valid_levels = ['low', 'medium', 'high', 'critical']
        if v not in valid_levels:
            raise ValueError(f'must be one of: {", ".join(valid_levels)}')
        return v
    
    @validator('recommendation_type')
    def validate_recommendation_type(cls, v):
        if v is None:
            return v
        valid_types = ['create_policy', 'update_policy', 'upload_document', 'training_needed', 'process_improvement', 'system_configuration']
        if v not in valid_types:
            raise ValueError(f'recommendation_type must be one of: {", ".join(valid_types)}')
        return v