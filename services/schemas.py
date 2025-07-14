from enum import Enum
from time import timezone
from pydantic import BaseModel, Field, validator
from typing import Any, List, Dict, Literal, Optional, Union
from datetime import datetime
from uuid import UUID
from decimal import Decimal

class GapType(str, Enum):
    MISSING_POLICY = "missing_policy"
    OUTDATED_POLICY = "outdated_policy"
    LOW_CONFIDENCE = "low_confidence"
    CONFLICTING_POLICIES = "conflicting_policies"
    INCOMPLETE_COVERAGE = "incomplete_coverage"
    NO_EVIDENCE = "no_evidence"

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class PriorityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class ComplianceImpact(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
class UploadResponse(BaseModel):
    message: str
    inserted_count: int
    ingestion_id: str = Field(description="UUID of the ingestion record")
    compliance_domain: Optional[str] = Field(None, description="Compliance domain assigned to the document")
    document_version: Optional[str] = Field(None, description="Document version")
    document_tags: Optional[List[str]] = Field(None, description="Document tags assigned")

class QueryRequest(BaseModel):
    question: str
    conversation_id: Optional[str] = Field(None, description="Conversation UUID")
    audit_session_id: Optional[str] = Field(None, description="Audit session UUID for compliance tracking")
    compliance_domain: Optional[str] = Field(None, description="Compliance domain (e.g., 'GDPR', 'ISO27001')")
    match_threshold: Optional[float] = Field(0.75, description="Similarity match threshold", ge=0.0, le=1.0)
    match_count: Optional[int] = Field(5, description="Maximum number of documents to retrieve", ge=1, le=20)
    user_id: Optional[str] = Field(None, description="User ID for audit tracking")
    document_version: Optional[str] = Field(None, description="Query document version")
    document_tags: Optional[List[str]] = Field(None, description="Query document tags")

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
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Aggregated metadata from the query")
    
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
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Aggregated metadata from source documents")

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

class ComplianceGap(BaseModel):
    """Model for compliance gaps used in generation methods"""
    id: Optional[str] = None
    gap_title: Optional[str] = None
    gap_description: Optional[str] = None
    gap_type: Optional[GapType] = None
    risk_level: Optional[RiskLevel] = None
    regulatory_requirement: Optional[str] = None
    compliance_domain: Optional[str] = None
    assigned_to: Optional[str] = None
    
    class Config:
        use_enum_values = True

class ConversationAnalysis(BaseModel):
    """Analysis of chat conversation"""
    total_interactions: int = Field(..., ge=0)
    unique_documents_referenced: int = Field(..., ge=0)
    coverage_areas: List[str] = Field(default_factory=list)
    avg_confidence_score: Optional[float] = Field(None, ge=0, le=1)
    low_confidence_interactions: int = Field(default=0, ge=0)

class GapsByType(BaseModel):
    """Gaps grouped by type - Updated to match database schema"""
    missing_policy: List[ComplianceGap] = Field(default_factory=list)
    outdated_policy: List[ComplianceGap] = Field(default_factory=list)
    low_confidence: List[ComplianceGap] = Field(default_factory=list)
    conflicting_policies: List[ComplianceGap] = Field(default_factory=list)
    incomplete_coverage: List[ComplianceGap] = Field(default_factory=list)
    no_evidence: List[ComplianceGap] = Field(default_factory=list)

class GapAnalysis(BaseModel):
    """Analysis of identified gaps"""
    gaps_by_type: GapsByType
    regulatory_gaps: List[ComplianceGap] = Field(default_factory=list)
    high_confidence_gaps: List[ComplianceGap] = Field(default_factory=list)  # Changed from process_gaps
    total_gaps: int = Field(..., ge=0)
    critical_gaps_count: int = Field(default=0, ge=0)
    high_risk_gaps_count: int = Field(default=0, ge=0)

class DocumentCoverage(BaseModel):
    """Analysis of document coverage"""
    documents_accessed: int = Field(..., ge=0)
    citation_frequency: Dict[str, int] = Field(default_factory=dict)
    most_referenced_documents: List[str] = Field(default_factory=list)
    coverage_percentage: Optional[float] = Field(None, ge=0, le=100)

class DetailedFindings(BaseModel):
    """Complete detailed findings structure"""
    conversation_analysis: ConversationAnalysis
    gap_analysis: GapAnalysis
    document_coverage: DocumentCoverage
    summary: Optional[str] = None
    key_insights: List[str] = Field(default_factory=list)
    
    class Config:
        use_enum_values = True

# Recommendation Models
class GeneratedRecommendation(BaseModel):
    """Generated recommendation structure"""
    id: Optional[str] = None
    title: str = Field(..., max_length=255)
    description: str
    priority: PriorityLevel
    recommendation_type: Optional[GapType] = None  # Based on gap type that triggered it
    
    # Implementation details
    action_items: List[str] = Field(default_factory=list)
    estimated_effort: Optional[str] = None
    estimated_cost: Optional[Decimal] = Field(None, ge=0)
    target_completion_date: Optional[datetime] = None
    
    # Impact and compliance
    compliance_impact: ComplianceImpact
    affected_gaps: List[str] = Field(default_factory=list)  # Gap IDs this addresses
    regulatory_requirements: List[str] = Field(default_factory=list)
    
    # Risk and business case
    risk_if_not_implemented: Optional[str] = None
    business_justification: Optional[str] = None
    success_metrics: List[str] = Field(default_factory=list)
    
    # Metadata
    created_at: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Config:
        use_enum_values = True

# Action Item Models
class GeneratedActionItem(BaseModel):
    """Generated action item structure"""
    id: Optional[str] = None
    title: str = Field(..., max_length=255)
    description: str
    priority: PriorityLevel
    
    # Assignment and timeline
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    estimated_effort: Optional[str] = None
    
    # Context and relationships
    gap_id: Optional[str] = None
    recommendation_id: Optional[str] = None
    compliance_domain: Optional[str] = None
    
    # Status and progress
    status: str = Field(default="not_started")
    progress_percentage: int = Field(default=0, ge=0, le=100)
    
    # Metadata
    created_at: Optional[datetime] = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    class Config:
        use_enum_values = True

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

    user_id: Optional[UUID] = None
    audit_session_id: Optional[UUID] = None
    compliance_domain: Optional[str] = Field(None, max_length=100)
    
    # Report metadata
    report_title: Optional[str] = Field(None, max_length=255)
    report_type: Optional[str] = None
    report_status: Optional[str] = None
    
    # Session data references
    chat_history_ids: Optional[List[int]] = None
    compliance_gap_ids: Optional[List[UUID]] = None
    document_ids: Optional[List[UUID]] = None
    pdf_ingestion_ids: Optional[List[UUID]] = None
    
    # Executive summary metrics
    total_questions_asked: Optional[int] = Field(None, ge=0)
    questions_answered_satisfactorily: Optional[int] = Field(None, ge=0)
    total_gaps_identified: Optional[int] = Field(None, ge=0)
    critical_gaps_count: Optional[int] = Field(None, ge=0)
    high_risk_gaps_count: Optional[int] = Field(None, ge=0)
    medium_risk_gaps_count: Optional[int] = Field(None, ge=0)
    low_risk_gaps_count: Optional[int] = Field(None, ge=0)
    
    # Compliance coverage analysis
    requirements_total: Optional[int] = Field(None, ge=0)
    requirements_covered: Optional[int] = Field(None, ge=0)
    coverage_percentage: Optional[Decimal] = Field(None, ge=0, le=100)
    policy_documents_referenced: Optional[int] = Field(None, ge=0)
    unique_sources_count: Optional[int] = Field(None, ge=0)
    
    # Time and performance metrics
    session_duration_minutes: Optional[int] = Field(None, ge=0)
    avg_response_time_ms: Optional[int] = Field(None, ge=0)
    total_tokens_used: Optional[int] = Field(None, ge=0)
    total_similarity_searches: Optional[int] = Field(None, ge=0)
    
    # Quality metrics
    avg_confidence_score: Optional[Decimal] = Field(None, ge=0, le=1)
    low_confidence_answers_count: Optional[int] = Field(None, ge=0)
    contradictory_findings_count: Optional[int] = Field(None, ge=0)
    outdated_references_count: Optional[int] = Field(None, ge=0)
    
    # Business impact assessment
    overall_compliance_rating: Optional[str] = None
    estimated_remediation_cost: Optional[Decimal] = Field(None, ge=0)
    estimated_remediation_time_days: Optional[int] = Field(None, ge=0)
    regulatory_risk_score: Optional[int] = Field(None, ge=1, le=10)
    potential_fine_exposure: Optional[Decimal] = Field(None, ge=0)
    
    # Report content and formatting
    executive_summary: Optional[str] = None
    detailed_findings: Optional[List[DetailedFindings]] = None
    recommendations: Optional[List[GeneratedRecommendation]] = None
    action_items: Optional[List[GeneratedActionItem]] = None
    appendices: Optional[Dict[str, Any]] = None
    
    # Report generation settings
    template_used: Optional[str] = Field(None, max_length=100)
    include_technical_details: Optional[bool] = None
    include_source_citations: Optional[bool] = None
    include_confidence_scores: Optional[bool] = None
    target_audience: Optional[str] = Field(None, max_length=100)
    
    # Distribution and approval workflow
    generated_by: Optional[UUID] = None
    reviewed_by: Optional[UUID] = None
    approved_by: Optional[UUID] = None
    distributed_to: Optional[List[str]] = None
    external_auditor_access: Optional[bool] = None
    confidentiality_level: Optional[str] = None
    
    # Regulatory and audit trail
    audit_trail: Optional[List[Dict[str, Any]]] = None
    external_audit_reference: Optional[str] = Field(None, max_length=100)
    regulatory_submission_date: Optional[datetime] = None
    regulatory_response_received: Optional[bool] = None
    
    # File and export metadata
    report_file_path: Optional[str] = None
    report_file_size: Optional[int] = Field(None, ge=0)
    report_hash: Optional[str] = Field(None, max_length=64)
    export_formats: Optional[List[str]] = None
    
    # Comparison and trending
    previous_report_id: Optional[UUID] = None
    improvement_from_previous: Optional[Decimal] = None
    trending_direction: Optional[str] = None
    benchmark_comparison: Optional[Dict[str, Any]] = None
    
    # Integration and automation
    scheduled_followup_date: Optional[datetime] = None
    auto_generated: Optional[bool] = None
    integration_exports: Optional[Dict[str, Any]] = None
    notification_sent: Optional[bool] = None
    
    # Validators
    @validator('report_type')
    def validate_report_type(cls, v):
        if v is None:
            return v
        valid_types = ['compliance_audit', 'gap_analysis', 'regulatory_review', 'external_audit', 'internal_review']
        if v not in valid_types:
            raise ValueError(f'report_type must be one of: {", ".join(valid_types)}')
        return v
    
    @validator('report_status')
    def validate_report_status(cls, v):
        if v is None:
            return v
        valid_statuses = ['draft', 'finalized', 'approved', 'distributed', 'archived']
        if v not in valid_statuses:
            raise ValueError(f'report_status must be one of: {", ".join(valid_statuses)}')
        return v
    
    @validator('overall_compliance_rating')
    def validate_compliance_rating(cls, v):
        if v is None:
            return v
        valid_ratings = ['excellent', 'good', 'fair', 'poor', 'critical']
        if v not in valid_ratings:
            raise ValueError(f'overall_compliance_rating must be one of: {", ".join(valid_ratings)}')
        return v
    
    @validator('trending_direction')
    def validate_trending_direction(cls, v):
        if v is None:
            return v
        valid_directions = ['improving', 'stable', 'declining']
        if v not in valid_directions:
            raise ValueError(f'trending_direction must be one of: {", ".join(valid_directions)}')
        return v
    
    @validator('confidentiality_level')
    def validate_confidentiality_level(cls, v):
        if v is None:
            return v
        valid_levels = ['public', 'internal', 'confidential', 'restricted']
        if v not in valid_levels:
            raise ValueError(f'confidentiality_level must be one of: {", ".join(valid_levels)}')
        return v
    
    @validator('target_audience')
    def validate_target_audience(cls, v):
        if v is None:
            return v
        # These are common values, but you may want to make this more flexible
        valid_audiences = ['executives', 'compliance_team', 'auditors', 'regulators', 'management', 'board']
        if v not in valid_audiences:
            # Allow custom audiences but log a warning
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Custom target_audience used: {v}")
        return v
    
    @validator('detailed_findings')
    def validate_detailed_findings(cls, v):
        """Validate detailed findings - accept both dict and structured object"""
        if v is None:
            return v
        
        if isinstance(v, DetailedFindings):
            return v
        elif isinstance(v, dict):
            # Try to convert dict to structured object
            try:
                return DetailedFindings(**v)
            except Exception:
                # If conversion fails, return as dict for backward compatibility
                return v
        elif isinstance(v, list):
            # Legacy format - convert to dict structure
            return {
                "findings": v,
                "metadata": {"converted_from_legacy": True}
            }
        else:
            raise ValueError("detailed_findings must be a dict, list, or DetailedFindings object")
    
    @validator('recommendations')
    def validate_recommendations(cls, v):
        """Validate recommendations - accept both dict list and structured objects"""
        if v is None:
            return v
        
        if isinstance(v, list):
            validated_recommendations = []
            for item in v:
                if isinstance(item, GeneratedRecommendation):
                    validated_recommendations.append(item)
                elif isinstance(item, dict):
                    # Try to convert dict to structured object
                    try:
                        validated_recommendations.append(GeneratedRecommendation(**item))
                    except Exception:
                        # If conversion fails, keep as dict for backward compatibility
                        validated_recommendations.append(item)
                else:
                    raise ValueError("Each recommendation must be a dict or GeneratedRecommendation object")
            return validated_recommendations
        else:
            raise ValueError("recommendations must be a list")
    
    @validator('action_items')
    def validate_action_items(cls, v):
        """Validate action items - accept both dict list and structured objects"""
        if v is None:
            return v
        
        if isinstance(v, list):
            validated_action_items = []
            for item in v:
                if isinstance(item, GeneratedActionItem):
                    validated_action_items.append(item)
                elif isinstance(item, dict):
                    # Try to convert dict to structured object
                    try:
                        validated_action_items.append(GeneratedActionItem(**item))
                    except Exception:
                        # If conversion fails, keep as dict for backward compatibility
                        validated_action_items.append(item)
                else:
                    raise ValueError("Each action item must be a dict or GeneratedActionItem object")
            return validated_action_items
        else:
            raise ValueError("action_items must be a list")
    
    @validator('distributed_to')
    def validate_distributed_to(cls, v):
        if v is None:
            return v
        # Basic email validation for distributed_to list
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        for email in v:
            if not re.match(email_pattern, email):
                raise ValueError(f'Invalid email address in distributed_to: {email}')
        return v
    
    @validator('regulatory_submission_date', 'scheduled_followup_date')
    def validate_future_dates(cls, v):
        if v is None:
            return v
        # You might want to allow past dates for regulatory_submission_date
        # but ensure scheduled_followup_date is reasonable
        return v
    
    @validator('questions_answered_satisfactorily')
    def validate_questions_answered(cls, v, values):
        if v is None:
            return v
        total_questions = values.get('total_questions_asked')
        if total_questions is not None and v > total_questions:
            raise ValueError('questions_answered_satisfactorily cannot exceed total_questions_asked')
        return v
    
    @validator('requirements_covered')
    def validate_requirements_covered(cls, v, values):
        if v is None:
            return v
        total_requirements = values.get('requirements_total')
        if total_requirements is not None and v > total_requirements:
            raise ValueError('requirements_covered cannot exceed requirements_total')
        return v
    
    class Config:
        # Allow extra fields in case you need to extend without breaking existing code
        extra = "forbid"
        # Use enum values for validation
        use_enum_values = True
        # Validate assignment to catch errors early
        validate_assignment = True

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
    document_tags: Optional[List[str]] = Field(None, description="Filter by document tags")
    tags_match_mode: str = Field("any", description="Tag matching mode: 'any', 'all', or 'exact'")
    skip: int = Field(0, ge=0, description="Number of records to skip")
    limit: int = Field(10, ge=1, le=100, description="Maximum number of records to return")
    
    @validator('tags_match_mode')
    def validate_match_mode(cls, v):
        valid_modes = ["any", "all", "exact"]
        if v not in valid_modes:
            raise ValueError(f'tags_match_mode must be one of: {", ".join(valid_modes)}')
        return v

class PdfIngestionWithTagsRequest(BaseModel):
    """Request model for filtering PDF ingestions by tags"""
    document_tags: List[str] = Field(..., description="List of tags to filter by")
    tags_match_mode: Literal["any", "all", "exact"] = Field("any", description="How to match tags")
    compliance_domain: Optional[str] = Field(None, description="Filter by compliance domain")
    uploaded_by: Optional[str] = Field(None, description="Filter by uploader")
    processing_status: Optional[str] = Field(None, description="Filter by processing status")
    skip: int = Field(0, ge=0, description="Records to skip")
    limit: int = Field(50, ge=1, le=100, description="Maximum records to return")
    
    @validator('tags_match_mode')
    def validate_match_mode(cls, v):
        valid_modes = ["any", "all", "exact"]
        if v not in valid_modes:
            raise ValueError(f'tags_match_mode must be one of: {", ".join(valid_modes)}')
        return v
    
    @validator('processing_status')
    def validate_processing_status(cls, v):
        if v is None:
            return v
        valid_statuses = ["processing", "completed", "failed", "deleted"]
        if v not in valid_statuses:
            raise ValueError(f'processing_status must be one of: {", ".join(valid_statuses)}')
        return v
    
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

class DocumentTagsRequest(BaseModel):
    document_tags: List[str] = Field(..., description="List of tags to filter by")
    tags_match_mode: Literal["any", "all", "exact"] = Field("any", description="How to match tags")
    compliance_domain: Optional[str] = Field(None, description="Filter by compliance domain")
    approval_status: Optional[str] = Field(None, description="Filter by approval status")
    uploaded_by: Optional[str] = Field(None, description="Filter by uploader")
    approved_by: Optional[str] = Field(None, description="Filter by approver")
    skip: int = Field(0, ge=0, description="Records to skip")
    limit: int = Field(50, ge=1, le=100, description="Maximum records to return")
    
    @validator('tags_match_mode')
    def validate_match_mode(cls, v):
        valid_modes = ["any", "all", "exact"]
        if v not in valid_modes:
            raise ValueError(f'tags_match_mode must be one of: {", ".join(valid_modes)}')
        return v
    
    @validator('approval_status')
    def validate_approval_status(cls, v):
        if v is None:
            return v
        valid_statuses = ["pending", "approved", "rejected", "deprecated"]
        if v not in valid_statuses:
            raise ValueError(f'approval_status must be one of: {", ".join(valid_statuses)}')
        return v

class AuditReportAccessLogRequest(BaseModel):
    distribution_id: UUID = Field(..., description="Distribution ID being accessed")
    access_ip_address: Optional[str] = Field(None, description="IP address of accessor")
    user_agent: Optional[str] = Field(None, description="User agent string")

class AuditSessionPdfIngestionRelationship(BaseModel):
    id: UUID = Field(..., description="Unique relationship identifier")
    audit_session_id: UUID = Field(..., description="Audit session ID")
    pdf_ingestion_id: UUID = Field(..., description="PDF ingestion ID")
    added_at: datetime = Field(..., description="When the relationship was created")
    added_by: UUID = Field(..., description="User who created the relationship")
    notes: Optional[str] = Field(None, description="Optional notes about the relationship")
    
    class Config:
        from_attributes = True

class AuditSessionPdfIngestionCreate(BaseModel):
    pdf_ingestion_id: UUID = Field(..., description="PDF ingestion ID to add")
    notes: Optional[str] = Field(None, description="Optional notes about why this PDF is relevant")

class AuditSessionPdfIngestionBulkCreate(BaseModel):
    pdf_ingestion_ids: List[UUID] = Field(..., description="List of PDF ingestion IDs to add")
    notes: Optional[str] = Field(None, description="Optional notes about why these PDFs are relevant")
    
    @validator('pdf_ingestion_ids')
    def validate_pdf_ingestion_ids(cls, v):
        if not v:
            raise ValueError('pdf_ingestion_ids cannot be empty')
        if len(v) > 50:  # Reasonable limit
            raise ValueError('Cannot add more than 50 PDF ingestions at once')
        return v

class AuditSessionPdfIngestionBulkRemove(BaseModel):
    pdf_ingestion_ids: List[UUID] = Field(..., description="List of PDF ingestion IDs to remove")
    
    @validator('pdf_ingestion_ids')
    def validate_pdf_ingestion_ids(cls, v):
        if not v:
            raise ValueError('pdf_ingestion_ids cannot be empty')
        return v

class PdfIngestionWithRelationship(BaseModel):
    id: UUID
    filename: str
    compliance_domain: Optional[str]
    document_version: Optional[str]
    uploaded_by: Optional[UUID]
    file_size: Optional[int]
    processing_status: str
    total_chunks: Optional[int]
    ingested_at: datetime
    metadata: Optional[Dict[str, Any]] = None
    document_tags: Optional[List[str]] = None
    relationship_id: UUID = Field(..., description="ID of the relationship record")
    added_at: datetime = Field(..., description="When added to the audit session")
    added_by: UUID = Field(..., description="User who added this PDF to the session")
    notes: Optional[str] = Field(None, description="Notes about the relationship")
    
    class Config:
        from_attributes = True

class AuditSessionWithRelationship(BaseModel):
    id: UUID
    user_id: UUID
    session_name: str
    compliance_domain: str
    started_at: datetime
    ended_at: Optional[datetime]
    total_queries: int
    session_summary: Optional[str]
    is_active: bool

    relationship_id: UUID = Field(..., description="ID of the relationship record")
    added_at: datetime = Field(..., description="When this session was linked to the PDF")
    added_by: UUID = Field(..., description="User who created the relationship")
    notes: Optional[str] = Field(None, description="Notes about the relationship")
    
    class Config:
        from_attributes = True

class AuditSessionPdfIngestionBulkResponse(BaseModel):
    added_relationships: List[AuditSessionPdfIngestionRelationship] = Field(default_factory=list)
    added_count: int = Field(0, description="Number of relationships created")
    skipped_existing: List[UUID] = Field(default_factory=list, description="PDF ingestion IDs that were already linked")
    skipped_count: int = Field(0, description="Number of relationships that were already existing")
    
class AuditSessionPdfIngestionBulkRemoveResponse(BaseModel):
    message: str
    removed_relationships: List[AuditSessionPdfIngestionRelationship] = Field(default_factory=list)
    removed_count: int = Field(0, description="Number of relationships removed")
    not_found_ids: List[UUID] = Field(default_factory=list, description="PDF ingestion IDs that were not linked")
    not_found_count: int = Field(0, description="Number of PDF ingestions that were not linked")
class AuditSessionResponseWithPdfCount(AuditSessionResponse):
    pdf_ingestions_count: int = Field(0, description="Number of PDF ingestions linked to this session")

class PdfIngestionResponseWithSessionCount(PdfIngestionResponse):
    audit_sessions_count: int = Field(0, description="Number of audit sessions linked to this PDF ingestion")

class AuditSessionSearchWithPdfFilters(AuditSessionSearchRequest):
    has_pdf_ingestions: Optional[bool] = Field(None, description="Filter sessions that have/don't have PDF ingestions")
    min_pdf_ingestions: Optional[int] = Field(None, ge=0, description="Minimum number of PDF ingestions")
    max_pdf_ingestions: Optional[int] = Field(None, ge=0, description="Maximum number of PDF ingestions")
    pdf_compliance_domain: Optional[str] = Field(None, description="Filter by compliance domain of linked PDFs")
    pdf_document_version: Optional[str] = Field(None, description="Filter by version of linked PDFs")
    pdf_uploaded_by: Optional[UUID] = Field(None, description="Filter by uploader of linked PDFs")

class PdfIngestionSearchWithSessionFilters(PdfIngestionSearchRequest):
    has_audit_sessions: Optional[bool] = Field(None, description="Filter PDFs that have/don't have audit sessions")
    min_audit_sessions: Optional[int] = Field(None, ge=0, description="Minimum number of audit sessions")
    max_audit_sessions: Optional[int] = Field(None, ge=0, description="Maximum number of audit sessions")
    session_compliance_domain: Optional[str] = Field(None, description="Filter by compliance domain of linked sessions")
    session_user_id: Optional[UUID] = Field(None, description="Filter by user ID of linked sessions")
    session_is_active: Optional[bool] = Field(None, description="Filter by active status of linked sessions")

class AuditSessionStatisticsWithPdf(BaseModel):
    total_sessions: int
    active_sessions: int
    completed_sessions: int
    total_queries: int
    avg_queries_per_session: float
    sessions_by_domain: Dict[str, int]
    sessions_by_user: Dict[str, int]

    sessions_with_pdfs: int = Field(0, description="Number of sessions with linked PDF ingestions")
    sessions_without_pdfs: int = Field(0, description="Number of sessions without linked PDF ingestions")
    total_pdf_ingestions_linked: int = Field(0, description="Total number of PDF ingestions linked across all sessions")
    avg_pdfs_per_session: float = Field(0.0, description="Average number of PDF ingestions per session")
    max_pdfs_in_session: int = Field(0, description="Maximum number of PDF ingestions in a single session")

    pdf_domains_by_session_domain: Dict[str, Dict[str, int]] = Field(
        default_factory=dict, 
        description="Breakdown of PDF compliance domains by session compliance domain"
    )
    
    filters_applied: Dict[str, Any]

class PdfIngestionStatisticsWithSessions(BaseModel):
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

    pdfs_with_sessions: int = Field(0, description="Number of PDF ingestions linked to audit sessions")
    pdfs_without_sessions: int = Field(0, description="Number of PDF ingestions not linked to any audit session")
    total_sessions_linked: int = Field(0, description="Total number of audit sessions linked across all PDFs")
    avg_sessions_per_pdf: float = Field(0.0, description="Average number of audit sessions per PDF ingestion")
    max_sessions_for_pdf: int = Field(0, description="Maximum number of audit sessions linked to a single PDF")

    most_referenced_pdfs: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="PDF ingestions referenced by the most audit sessions"
    )
    
    filters_applied: Dict[str, Any]
class AuditSessionPdfIngestionFilters(BaseModel):
    audit_session_id: Optional[UUID] = Field(None, description="Filter by audit session")
    pdf_ingestion_id: Optional[UUID] = Field(None, description="Filter by PDF ingestion")
    added_by: Optional[UUID] = Field(None, description="Filter by user who created the relationship")
    added_after: Optional[datetime] = Field(None, description="Filter relationships created after this date")
    added_before: Optional[datetime] = Field(None, description="Filter relationships created before this date")
    has_notes: Optional[bool] = Field(None, description="Filter relationships that have/don't have notes")
    skip: int = Field(0, ge=0, description="Records to skip")
    limit: int = Field(10, ge=1, le=100, description="Maximum records to return")

class RelationshipSummary(BaseModel):
    total_relationships: int
    unique_audit_sessions: int
    unique_pdf_ingestions: int
    relationships_with_notes: int
    relationships_by_user: Dict[str, int]
    relationships_by_domain: Dict[str, int]
    recent_relationships: List[AuditSessionPdfIngestionRelationship]
    
class CrossReferenceAnalysis(BaseModel):
    session_domain: str
    linked_pdf_domains: Dict[str, int]
    total_pdfs_linked: int
    cross_domain_percentage: float = Field(description="Percentage of PDFs from different domains")
    
class ComplianceCoverageAnalysis(BaseModel):
    audit_session_id: UUID
    session_compliance_domain: str
    linked_pdf_count: int
    covered_domains: List[str]
    domain_coverage: Dict[str, Dict[str, Any]]  # domain -> {pdf_count, latest_version, etc.}
    coverage_gaps: List[str] = Field(description="Domains that might need more documentation")
    coverage_score: float = Field(ge=0, le=1, description="Overall coverage score (0-1)")
    recommendations: List[str] = Field(description="Recommendations for improving coverage")

class DocumentTagConstants:    
    DOCUMENT_TYPES = {
        "reference_document": "ISO norms, GDPR regulations, standards",
        "implementation_document": "SOPs, procedures, policies", 
        "assessment_document": "audit reports, gap analyses",
        "training_document": "training materials, guidelines",
        "template_document": "document templates, forms"
    }
    
    SOURCE_TYPES = {
        "iso_standard": "ISO 27001, ISO 9001, etc.",
        "regulatory_framework": "GDPR, SOX, HIPAA, etc.",
        "internal_policy": "Company-specific policies",
        "sop": "Standard Operating Procedures",
        "procedure": "Detailed procedures", 
        "guideline": "Implementation guidelines",
        "checklist": "Compliance checklists"
    }
    
    STATUS_TAGS = {
        "current": "Currently valid documents",
        "draft": "Draft versions", 
        "archived": "Historical versions",
        "superseded": "Replaced by newer versions"
    }
    
    SCOPE_TAGS = {
        "organizational": "Organization-wide applicability",
        "departmental": "Department-specific",
        "process_specific": "Specific to certain processes",
        "role_specific": "For specific roles/positions"
    }
    
    FORMAT_TAGS = {
        "policy_document": "High-level policies",
        "technical_specification": "Technical requirements",
        "process_flow": "Process descriptions", 
        "control_framework": "Control descriptions",
        "risk_matrix": "Risk assessments"
    }
    
    @classmethod
    def get_all_valid_tags(cls) -> List[str]:
        return (list(cls.DOCUMENT_TYPES.keys()) + list(cls.SOURCE_TYPES.keys()) + 
                list(cls.STATUS_TAGS.keys()) + list(cls.SCOPE_TAGS.keys()) + list(cls.FORMAT_TAGS.keys()))
    
    @classmethod
    def get_all_tags_with_descriptions(cls) -> Dict[str, str]:
        all_tags = {}
        all_tags.update(cls.DOCUMENT_TYPES)
        all_tags.update(cls.SOURCE_TYPES)
        all_tags.update(cls.STATUS_TAGS)
        all_tags.update(cls.SCOPE_TAGS)
        all_tags.update(cls.FORMAT_TAGS)
        return all_tags
    
    @classmethod
    def get_tags_by_category(cls) -> Dict[str, Dict[str, str]]:
        return {
            "document_types": cls.DOCUMENT_TYPES,
            "source_types": cls.SOURCE_TYPES,
            "status_tags": cls.STATUS_TAGS,
            "scope_tags": cls.SCOPE_TAGS,
            "format_tags": cls.FORMAT_TAGS
        }
    
    @classmethod
    def get_reference_document_tags(cls) -> List[str]:
        return ["reference_document", "iso_standard", "regulatory_framework", "current"]
    
    @classmethod  
    def get_implementation_document_tags(cls) -> List[str]:
        return ["implementation_document", "sop", "procedure", "internal_policy", "current"]
    
    @classmethod
    def get_tag_description(cls, tag: str) -> Optional[str]:
        all_tags = cls.get_all_tags_with_descriptions()
        return all_tags.get(tag)
    
    @classmethod
    def get_category_for_tag(cls, tag: str) -> Optional[str]:
        if tag in cls.DOCUMENT_TYPES:
            return "document_types"
        elif tag in cls.SOURCE_TYPES:
            return "source_types"
        elif tag in cls.STATUS_TAGS:
            return "status_tags"
        elif tag in cls.SCOPE_TAGS:
            return "scope_tags"
        elif tag in cls.FORMAT_TAGS:
            return "format_tags"
        else:
            return None