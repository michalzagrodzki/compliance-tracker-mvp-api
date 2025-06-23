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
    audit_session_id: Optional[str] = Field(None, description="Audit session UUID for compliance tracking")
    compliance_domain: Optional[str] = Field(None, description="Compliance domain (e.g., 'GDPR', 'ISO27001')")
    match_threshold: Optional[float] = Field(0.75, description="Similarity match threshold", ge=0.0, le=1.0)
    match_count: Optional[int] = Field(5, description="Maximum number of documents to retrieve", ge=1, le=20)
    user_id: Optional[str] = Field(None, description="User ID for audit tracking")

class SourceDoc(BaseModel):
    page_content: str | None = None
    metadata: Dict[str, Any]
    similarity: float | None = None
    id: str

class QueryResponse(BaseModel):
    answer: str
    source_docs: List[SourceDoc]
    conversation_id: str
    audit_session_id: Optional[str] = None
    compliance_domain: Optional[str] = None
    response_time_ms: Optional[int] = None
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
    session_name: str = Field(..., description="Session name string")
    compliance_domain: str = Field(..., description="Session name string")

class AuditSessionCreateResponse(BaseModel):
    id: UUID = Field(..., description="Unique session identifier")
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

class AuditReportCreate(BaseModel):
    """Request model for creating a new audit report"""
    user_id: UUID = Field(..., description="User who is generating the report")
    audit_session_id: UUID = Field(..., description="Audit session this report covers")
    compliance_domain: str = Field(..., description="Compliance domain code (e.g., GDPR, ISO27001)")
    
    report_title: str = Field(..., max_length=255, description="Title of the audit report")
    report_type: str = Field("compliance_audit", description="Type of audit report")
    
    # Optional filters for report generation
    chat_history_ids: Optional[List[int]] = Field(None, description="Specific chat interactions to include")
    compliance_gap_ids: Optional[List[UUID]] = Field(None, description="Specific gaps to include")
    document_ids: Optional[List[UUID]] = Field(None, description="Specific documents to reference")
    pdf_ingestion_ids: Optional[List[UUID]] = Field(None, description="Specific PDF sources to include")
    
    # Report configuration
    include_technical_details: bool = Field(False, description="Include technical details in report")
    include_source_citations: bool = Field(True, description="Include source document citations")
    include_confidence_scores: bool = Field(False, description="Include confidence scores")
    target_audience: str = Field("compliance_team", description="Target audience for the report")
    template_used: Optional[str] = Field(None, max_length=100, description="Report template identifier")
    
    # Distribution settings
    confidentiality_level: str = Field("internal", description="Confidentiality classification")
    external_auditor_access: bool = Field(False, description="Allow external auditor access")
    
    @validator('report_type')
    def validate_report_type(cls, v):
        valid_types = ['compliance_audit', 'gap_analysis', 'regulatory_review', 'external_audit', 'internal_review']
        if v not in valid_types:
            raise ValueError(f'report_type must be one of: {", ".join(valid_types)}')
        return v
    
    @validator('target_audience')
    def validate_target_audience(cls, v):
        valid_audiences = ['executives', 'compliance_team', 'auditors', 'regulators', 'board']
        if v not in valid_audiences:
            raise ValueError(f'target_audience must be one of: {", ".join(valid_audiences)}')
        return v
    
    @validator('confidentiality_level')
    def validate_confidentiality_level(cls, v):
        valid_levels = ['public', 'internal', 'confidential', 'restricted']
        if v not in valid_levels:
            raise ValueError(f'confidentiality_level must be one of: {", ".join(valid_levels)}')
        return v

class AuditReportUpdate(BaseModel):
    """Request model for updating an audit report"""
    report_title: Optional[str] = Field(None, max_length=255)
    report_status: Optional[str] = None
    executive_summary: Optional[str] = None
    detailed_findings: Optional[Dict[str, Any]] = None
    recommendations: Optional[List[Dict[str, Any]]] = None
    action_items: Optional[List[Dict[str, Any]]] = None
    appendices: Optional[Dict[str, Any]] = None
    
    # Workflow fields
    reviewed_by: Optional[UUID] = None
    approved_by: Optional[UUID] = None
    external_audit_reference: Optional[str] = Field(None, max_length=100)
    regulatory_submission_date: Optional[datetime] = None
    regulatory_response_received: Optional[bool] = None
    
    # File metadata
    report_file_path: Optional[str] = None
    report_file_size: Optional[int] = None
    report_hash: Optional[str] = Field(None, max_length=64)
    export_formats: Optional[List[str]] = None
    
    # Comparison fields
    previous_report_id: Optional[UUID] = None
    improvement_from_previous: Optional[Decimal] = None
    trending_direction: Optional[str] = None
    benchmark_comparison: Optional[Dict[str, Any]] = None
    
    @validator('report_status')
    def validate_report_status(cls, v):
        if v is None:
            return v
        valid_statuses = ['draft', 'finalized', 'approved', 'distributed', 'archived']
        if v not in valid_statuses:
            raise ValueError(f'report_status must be one of: {", ".join(valid_statuses)}')
        return v
    
    @validator('trending_direction')
    def validate_trending_direction(cls, v):
        if v is None:
            return v
        valid_directions = ['improving', 'stable', 'declining']
        if v not in valid_directions:
            raise ValueError(f'trending_direction must be one of: {", ".join(valid_directions)}')
        return v

class AuditReportResponse(BaseModel):
    """Response model for audit report data"""
    id: UUID
    user_id: UUID
    audit_session_id: UUID
    compliance_domain: str
    
    report_title: str
    report_type: str
    report_status: str
    
    # Session data references
    chat_history_ids: List[int] = Field(default_factory=list)
    compliance_gap_ids: List[UUID] = Field(default_factory=list)
    document_ids: List[UUID] = Field(default_factory=list)
    pdf_ingestion_ids: List[UUID] = Field(default_factory=list)
    
    # Executive summary metrics
    total_questions_asked: int = 0
    questions_answered_satisfactorily: int = 0
    total_gaps_identified: int = 0
    critical_gaps_count: int = 0
    high_risk_gaps_count: int = 0
    medium_risk_gaps_count: int = 0
    low_risk_gaps_count: int = 0
    
    # Compliance coverage analysis
    requirements_total: Optional[int] = None
    requirements_covered: Optional[int] = None
    coverage_percentage: Optional[Decimal] = None
    policy_documents_referenced: int = 0
    unique_sources_count: int = 0
    
    # Performance metrics
    session_duration_minutes: Optional[int] = None
    avg_response_time_ms: Optional[int] = None
    total_tokens_used: Optional[int] = None
    total_similarity_searches: Optional[int] = None
    
    # Quality metrics
    avg_confidence_score: Optional[Decimal] = None
    low_confidence_answers_count: int = 0
    contradictory_findings_count: int = 0
    outdated_references_count: int = 0
    
    # Business impact
    overall_compliance_rating: Optional[str] = None
    estimated_remediation_cost: Optional[Decimal] = None
    estimated_remediation_time_days: Optional[int] = None
    regulatory_risk_score: Optional[int] = None
    potential_fine_exposure: Optional[Decimal] = None
    
    # Report content
    executive_summary: Optional[str] = None
    detailed_findings: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[Dict[str, Any]] = Field(default_factory=list)
    action_items: List[Dict[str, Any]] = Field(default_factory=list)
    appendices: Dict[str, Any] = Field(default_factory=dict)
    
    # Generation settings
    template_used: Optional[str] = None
    include_technical_details: bool = False
    include_source_citations: bool = True
    include_confidence_scores: bool = False
    target_audience: str = "compliance_team"
    
    # Workflow tracking
    generated_by: Optional[UUID] = None
    reviewed_by: Optional[UUID] = None
    approved_by: Optional[UUID] = None
    distributed_to: List[str] = Field(default_factory=list)
    external_auditor_access: bool = False
    confidentiality_level: str = "internal"
    
    # Regulatory tracking
    audit_trail: List[Dict[str, Any]] = Field(default_factory=list)
    external_audit_reference: Optional[str] = None
    regulatory_submission_date: Optional[datetime] = None
    regulatory_response_received: bool = False
    
    # File metadata
    report_file_path: Optional[str] = None
    report_file_size: Optional[int] = None
    report_hash: Optional[str] = None
    export_formats: List[str] = Field(default_factory=lambda: ['pdf'])
    
    # Comparison data
    previous_report_id: Optional[UUID] = None
    improvement_from_previous: Optional[Decimal] = None
    trending_direction: Optional[str] = None
    benchmark_comparison: Dict[str, Any] = Field(default_factory=dict)
    
    # Integration
    scheduled_followup_date: Optional[datetime] = None
    auto_generated: bool = False
    integration_exports: Dict[str, Any] = Field(default_factory=dict)
    notification_sent: bool = False
    
    # Timestamps
    report_generated_at: datetime
    report_finalized_at: Optional[datetime] = None
    last_modified_at: datetime
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class AuditReportVersionCreate(BaseModel):
    """Request model for creating a new audit report version"""
    change_description: str = Field(..., description="Description of changes made")
    change_type: str = Field(..., description="Type of change being made")
    
    @validator('change_type')
    def validate_change_type(cls, v):
        valid_types = ['draft_update', 'review_feedback', 'approval_change', 'correction', 'regulatory_update']
        if v not in valid_types:
            raise ValueError(f'change_type must be one of: {", ".join(valid_types)}')
        return v

class AuditReportVersionResponse(BaseModel):
    """Response model for audit report version"""
    id: UUID
    audit_report_id: UUID
    version_number: int
    change_description: Optional[str]
    changed_by: Optional[UUID]
    change_type: str
    report_snapshot: Dict[str, Any]
    created_at: datetime
    
    class Config:
        from_attributes = True

class AuditReportDistributionCreate(BaseModel):
    """Request model for distributing an audit report"""
    distributed_to: str = Field(..., max_length=255, description="Email or system identifier")
    distribution_method: str = Field(..., description="Method of distribution")
    distribution_format: str = Field(..., description="Format for distribution")
    
    external_reference: Optional[str] = Field(None, max_length=100, description="External system reference")
    expiry_date: Optional[datetime] = Field(None, description="When access expires")
    
    @validator('distribution_method')
    def validate_distribution_method(cls, v):
        valid_methods = ['email', 'portal_download', 'api_export', 'grc_system', 'secure_link']
        if v not in valid_methods:
            raise ValueError(f'distribution_method must be one of: {", ".join(valid_methods)}')
        return v
    
    @validator('distribution_format')
    def validate_distribution_format(cls, v):
        valid_formats = ['pdf', 'docx', 'html', 'json', 'csv']
        if v not in valid_formats:
            raise ValueError(f'distribution_format must be one of: {", ".join(valid_formats)}')
        return v

class AuditReportDistributionResponse(BaseModel):
    """Response model for audit report distribution"""
    id: UUID
    audit_report_id: UUID
    distributed_to: str
    distribution_method: str
    distribution_format: str
    
    # Access tracking
    accessed_at: Optional[datetime] = None
    download_count: int = 0
    last_accessed_at: Optional[datetime] = None
    access_ip_address: Optional[str] = None
    
    # Distribution metadata
    external_reference: Optional[str] = None
    expiry_date: Optional[datetime] = None
    is_active: bool = True
    
    distributed_at: datetime
    distributed_by: Optional[UUID] = None
    
    class Config:
        from_attributes = True

class AuditReportGenerateRequest(BaseModel):
    """Request model for generating an audit report from an audit session"""
    audit_session_id: UUID = Field(..., description="Audit session to generate report from")
    report_title: str = Field(..., max_length=255, description="Title for the report")
    report_type: str = Field("compliance_audit", description="Type of report to generate")
    
    # Generation options
    include_all_conversations: bool = Field(True, description="Include all conversations from session")
    include_identified_gaps: bool = Field(True, description="Include compliance gaps found")
    include_document_references: bool = Field(True, description="Include document references")
    generate_recommendations: bool = Field(True, description="Auto-generate recommendations")
    
    # Report configuration
    include_technical_details: bool = Field(False, description="Include technical details")
    include_source_citations: bool = Field(True, description="Include source citations")
    include_confidence_scores: bool = Field(False, description="Include confidence scores")
    target_audience: str = Field("compliance_team", description="Target audience")
    
    # Distribution settings
    confidentiality_level: str = Field("internal", description="Confidentiality level")
    auto_distribute: bool = Field(False, description="Auto-distribute to stakeholders")
    distribution_list: Optional[List[str]] = Field(None, description="Email list for distribution")
    
    @validator('report_type')
    def validate_report_type(cls, v):
        valid_types = ['compliance_audit', 'gap_analysis', 'regulatory_review', 'external_audit', 'internal_review']
        if v not in valid_types:
            raise ValueError(f'report_type must be one of: {", ".join(valid_types)}')
        return v

class AuditReportStatusUpdate(BaseModel):
    """Request model for updating audit report status"""
    new_status: str = Field(..., description="New status for the report")
    notes: Optional[str] = Field(None, description="Notes about the status change")
    
    @validator('new_status')
    def validate_new_status(cls, v):
        valid_statuses = ['draft', 'finalized', 'approved', 'distributed', 'archived']
        if v not in valid_statuses:
            raise ValueError(f'new_status must be one of: {", ".join(valid_statuses)}')
        return v

class AuditReportSearchRequest(BaseModel):
    """Request model for searching audit reports"""
    compliance_domain: Optional[str] = Field(None, description="Filter by compliance domain")
    report_type: Optional[str] = Field(None, description="Filter by report type")
    report_status: Optional[str] = Field(None, description="Filter by report status")
    user_id: Optional[UUID] = Field(None, description="Filter by creator")
    audit_session_id: Optional[UUID] = Field(None, description="Filter by audit session")
    generated_after: Optional[datetime] = Field(None, description="Filter by generation date (after)")
    generated_before: Optional[datetime] = Field(None, description="Filter by generation date (before)")
    target_audience: Optional[str] = Field(None, description="Filter by target audience")
    confidentiality_level: Optional[str] = Field(None, description="Filter by confidentiality level")
    skip: int = Field(0, ge=0, description="Records to skip")
    limit: int = Field(10, ge=1, le=100, description="Maximum records to return")

class AuditReportStatisticsResponse(BaseModel):
    """Response model for audit report statistics"""
    total_reports: int
    reports_by_status: Dict[str, int]
    reports_by_type: Dict[str, int]
    reports_by_domain: Dict[str, int]
    reports_by_audience: Dict[str, int]
    
    # Quality metrics
    avg_coverage_percentage: Optional[Decimal] = None
    avg_gaps_per_report: Optional[Decimal] = None
    avg_remediation_cost: Optional[Decimal] = None
    
    # Trend data
    reports_this_month: int = 0
    reports_last_month: int = 0
    month_over_month_change: Optional[Decimal] = None
    
    # Distribution metrics
    total_distributions: int = 0
    avg_distributions_per_report: Optional[Decimal] = None
    
    filters_applied: Dict[str, Any] = Field(default_factory=dict)

class AuditReportBulkActionRequest(BaseModel):
    """Request model for bulk actions on audit reports"""
    report_ids: List[UUID] = Field(..., description="List of report IDs")
    action: str = Field(..., description="Action to perform")
    
    # Action-specific parameters
    new_status: Optional[str] = Field(None, description="New status (for status updates)")
    distribution_list: Optional[List[str]] = Field(None, description="Distribution list (for bulk distribution)")
    distribution_format: Optional[str] = Field("pdf", description="Format for distribution")
    archive_reason: Optional[str] = Field(None, description="Reason for archiving")
    
    @validator('action')
    def validate_action(cls, v):
        valid_actions = ['update_status', 'distribute', 'archive', 'export', 'delete']
        if v not in valid_actions:
            raise ValueError(f'action must be one of: {", ".join(valid_actions)}')
        return v

class AuditReportAccessLogRequest(BaseModel):
    """Request model for logging report access"""
    distribution_id: UUID = Field(..., description="Distribution ID being accessed")
    access_ip_address: Optional[str] = Field(None, description="IP address of accessor")
    user_agent: Optional[str] = Field(None, description="User agent string")

class PdfIngestionSearchRequest(BaseModel):
    compliance_domain: Optional[str] = Field(None, description="Filter by compliance domain")
    uploaded_by: Optional[str] = Field(None, description="Filter by user ID who uploaded")
    document_version: Optional[str] = Field(None, description="Filter by document version (partial match)")
    processing_status: Optional[str] = Field(None, description="Filter by processing status")
    filename_search: Optional[str] = Field(None, description="Search in filename (partial match)")
    ingested_after: Optional[datetime] = Field(None, description="Filter ingestions after this date")
    ingested_before: Optional[datetime] = Field(None, description="Filter ingestions before this date")
    skip: int = Field(0, ge=0, description="Number of records to skip")
    limit: int = Field(10, ge=1, le=100, description="Maximum number of records to return")

class PdfIngestionResponse(BaseModel):
    id: str
    filename: str
    compliance_domain: Optional[str]
    document_version: Optional[str]
    uploaded_by: Optional[str]
    file_size: Optional[int]
    file_hash: Optional[str]
    processing_status: str
    total_chunks: Optional[int]
    error_message: Optional[str]
    ingested_at: datetime
    metadata: Optional[Dict[str, Any]] = None

class PdfIngestionStatisticsResponse(BaseModel):
    total_ingestions: int
    completed_ingestions: int
    failed_ingestions: int
    processing_ingestions: int
    success_rate: float
    total_chunks_created: int
    total_file_size_bytes: int
    avg_chunks_per_document: float
    ingestions_by_domain: Dict[str, int]
    ingestions_by_user: Dict[str, int]
    ingestions_by_version: Dict[str, int]
    filters_applied: Dict[str, Any]