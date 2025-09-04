"""
ComplianceGap entity model for the domain layer.
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from decimal import Decimal
from pydantic import BaseModel, Field, validator
from enum import Enum
from uuid import UUID


class GapType(str, Enum):
    """Types of compliance gaps."""
    MISSING_POLICY = "missing_policy"
    OUTDATED_POLICY = "outdated_policy"
    LOW_CONFIDENCE = "low_confidence"
    CONFLICTING_POLICIES = "conflicting_policies"
    INCOMPLETE_COVERAGE = "incomplete_coverage"
    NO_EVIDENCE = "no_evidence"


class RiskLevel(str, Enum):
    """Risk level classifications."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class BusinessImpact(str, Enum):
    """Business impact levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class GapStatus(str, Enum):
    """Compliance gap status."""
    IDENTIFIED = "identified"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class DetectionMethod(str, Enum):
    """How the gap was detected. Must match DB CHECK constraint."""
    QUERY_ANALYSIS = "query_analysis"
    PERIODIC_SCAN = "periodic_scan"
    DOCUMENT_UPLOAD = "document_upload"
    MANUAL_REVIEW = "manual_review"
    EXTERNAL_AUDIT = "external_audit"


class ComplianceGap(BaseModel):
    """
    ComplianceGap entity representing a compliance gap in the system.
    """
    id: str
    user_id: str  # User who identified the gap
    audit_session_id: str  # Audit session where gap was identified
    compliance_domain: str  # e.g., "GDPR", "ISO27001"
    
    # Gap classification
    gap_type: GapType
    gap_category: str  # Specific category within compliance domain
    gap_title: str
    gap_description: str
    
    # Original context
    original_question: str
    chat_history_id: Optional[str] = None
    pdf_ingestion_id: Optional[str] = None
    
    # Search/detection details
    expected_answer_type: Optional[str] = None
    search_terms_used: Optional[List[str]] = Field(default_factory=list)
    similarity_threshold_used: Optional[Decimal] = None
    best_match_score: Optional[Decimal] = None
    detection_method: DetectionMethod = DetectionMethod.QUERY_ANALYSIS
    confidence_score: Optional[Decimal] = None
    false_positive_likelihood: Optional[Decimal] = None
    
    # Risk and impact assessment
    risk_level: RiskLevel = RiskLevel.MEDIUM
    business_impact: BusinessImpact = BusinessImpact.MEDIUM
    regulatory_requirement: bool = False
    potential_fine_amount: Optional[Decimal] = None
    
    # Status and assignment
    status: GapStatus = GapStatus.IDENTIFIED
    assigned_to: Optional[str] = None  # User ID
    due_date: Optional[datetime] = None
    
    # Resolution tracking
    resolution_notes: Optional[str] = None
    recommendation_type: Optional[str] = None
    recommendation_text: Optional[str] = None
    recommended_actions: Optional[List[str]] = Field(default_factory=list)
    related_documents: Optional[List[str]] = Field(default_factory=list)
    
    # Timestamps
    detected_at: datetime
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    last_reviewed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    
    # Audit fields
    auto_generated: bool = True
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_context: Optional[Dict[str, Any]] = Field(default_factory=dict)

    class Config:
        from_attributes = True
        use_enum_values = True

    @validator('risk_level', pre=True)
    def validate_risk_level(cls, v):
        if isinstance(v, str):
            return RiskLevel(v)
        return v

    @validator('user_id', 'audit_session_id', pre=True)
    def _coerce_ids_to_str(cls, v):
        if isinstance(v, UUID):
            return str(v)
        return v

    @validator('status', pre=True)
    def validate_status(cls, v):
        if isinstance(v, str):
            return GapStatus(v)
        return v

    @validator('gap_type', pre=True)
    def validate_gap_type(cls, v):
        if isinstance(v, str):
            return GapType(v)
        return v

    def is_critical(self) -> bool:
        """Check if the gap has critical risk level."""
        return self.risk_level == RiskLevel.CRITICAL

    def is_regulatory(self) -> bool:
        """Check if the gap is a regulatory requirement."""
        return self.regulatory_requirement

    def is_resolved(self) -> bool:
        """Check if the gap has been resolved."""
        return self.status == GapStatus.RESOLVED

    def is_assigned(self) -> bool:
        """Check if the gap is assigned to someone."""
        return self.assigned_to is not None

    def is_overdue(self) -> bool:
        """Check if the gap is overdue (has due date in the past and not resolved)."""
        if self.due_date is None or self.is_resolved():
            return False
        now = datetime.now(timezone.utc)
        due = self.due_date
        if due.tzinfo is None:
            due = due.replace(tzinfo=timezone.utc)
        return now > due

    def acknowledge(self, user_id: str) -> None:
        """Mark the gap as acknowledged."""
        if self.status == GapStatus.IDENTIFIED:
            self.status = GapStatus.ACKNOWLEDGED
            self.acknowledged_at = datetime.now(timezone.utc)
            self.updated_at = datetime.now(timezone.utc)

    def assign_to(self, user_id: str, due_date: Optional[datetime] = None) -> None:
        """Assign the gap to a user."""
        self.assigned_to = user_id
        if due_date:
            self.due_date = due_date
        self.updated_at = datetime.now(timezone.utc)
        
        # If gap was just identified, acknowledge it
        if self.status == GapStatus.IDENTIFIED:
            self.acknowledge(user_id)

    def start_resolution(self) -> None:
        """Mark the gap as being worked on."""
        if self.status in [GapStatus.IDENTIFIED, GapStatus.ACKNOWLEDGED]:
            self.status = GapStatus.IN_PROGRESS
            self.updated_at = datetime.now(timezone.utc)

    def resolve(self, resolution_notes: Optional[str] = None) -> None:
        """Mark the gap as resolved."""
        self.status = GapStatus.RESOLVED
        self.resolved_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
        if resolution_notes:
            self.resolution_notes = resolution_notes

    def mark_false_positive(self, notes: Optional[str] = None) -> None:
        """Mark the gap as a false positive."""
        self.status = GapStatus.FALSE_POSITIVE
        self.resolved_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
        if notes:
            self.resolution_notes = notes

    def accept_risk(self, notes: Optional[str] = None) -> None:
        """Accept the risk and close the gap."""
        self.status = GapStatus.ACCEPTED_RISK
        self.resolved_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
        if notes:
            self.resolution_notes = notes

    def review(self, reviewer_id: str) -> None:
        """Mark the gap as reviewed."""
        self.last_reviewed_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def update_risk_assessment(self, risk_level: RiskLevel, business_impact: BusinessImpact, 
                              potential_fine: Optional[Decimal] = None) -> None:
        """Update risk assessment."""
        self.risk_level = risk_level
        self.business_impact = business_impact
        if potential_fine is not None:
            self.potential_fine_amount = potential_fine
        self.updated_at = datetime.now(timezone.utc)

    def add_recommendation(self, recommendation_type: str, recommendation_text: str, 
                          recommended_actions: Optional[List[str]] = None) -> None:
        """Add or update recommendations."""
        self.recommendation_type = recommendation_type
        self.recommendation_text = recommendation_text
        if recommended_actions:
            self.recommended_actions = recommended_actions
        self.updated_at = datetime.now(timezone.utc)

    def get_age_in_days(self) -> int:
        """Get the age of the gap in days."""
        now = datetime.now(timezone.utc)
        detected = self.detected_at
        if detected.tzinfo is None:
            detected = detected.replace(tzinfo=timezone.utc)
        return (now - detected).days

    def get_resolution_time_days(self) -> Optional[int]:
        """Get resolution time in days if resolved."""
        if self.resolved_at:
            detected = self.detected_at
            resolved = self.resolved_at
            if detected.tzinfo is None:
                detected = detected.replace(tzinfo=timezone.utc)
            if resolved.tzinfo is None:
                resolved = resolved.replace(tzinfo=timezone.utc)
            return (resolved - detected).days
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert gap to dictionary for database storage."""
        data = self.model_dump()
        
        # Ensure datetime fields are in ISO format
        datetime_fields = ['detected_at', 'acknowledged_at', 'resolved_at', 
                          'last_reviewed_at', 'created_at', 'updated_at', 'due_date']
        
        for field in datetime_fields:
            if data.get(field):
                if isinstance(data[field], datetime):
                    data[field] = data[field].isoformat()
        
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComplianceGap":
        """Create ComplianceGap from dictionary data."""
        # Parse datetime strings
        datetime_fields = ['detected_at', 'acknowledged_at', 'resolved_at', 
                          'last_reviewed_at', 'created_at', 'updated_at', 'due_date']
        
        for field in datetime_fields:
            if data.get(field) and isinstance(data[field], str):
                try:
                    data[field] = datetime.fromisoformat(data[field].replace('Z', '+00:00'))
                except ValueError:
                    # Handle other date formats if needed
                    pass
        
        # Handle decimal fields
        decimal_fields = ['similarity_threshold_used', 'best_match_score', 
                         'confidence_score', 'false_positive_likelihood', 'potential_fine_amount']
        
        for field in decimal_fields:
            if data.get(field) and not isinstance(data[field], Decimal):
                try:
                    data[field] = Decimal(str(data[field]))
                except (ValueError, TypeError):
                    pass
        
        # Handle string fields that might come as integers from database
        string_fields = ['chat_history_id']
        for field in string_fields:
            if data.get(field) is not None and not isinstance(data[field], str):
                data[field] = str(data[field])
        
        return cls(**data)


class ComplianceGapCreate(BaseModel):
    """Model for creating a new compliance gap."""
    user_id: str
    audit_session_id: str
    compliance_domain: str
    gap_type: GapType
    gap_category: str
    gap_title: str
    gap_description: str
    original_question: str
    
    # Optional fields
    chat_history_id: Optional[str] = None
    pdf_ingestion_id: Optional[str] = None
    expected_answer_type: Optional[str] = None
    search_terms_used: Optional[List[str]] = Field(default_factory=list)
    similarity_threshold_used: Optional[Decimal] = None
    best_match_score: Optional[Decimal] = None
    detection_method: DetectionMethod = DetectionMethod.QUERY_ANALYSIS
    confidence_score: Optional[Decimal] = None
    risk_level: RiskLevel = RiskLevel.MEDIUM
    business_impact: BusinessImpact = BusinessImpact.MEDIUM
    regulatory_requirement: bool = False
    potential_fine_amount: Optional[Decimal] = None

    # Optional remediation and references
    recommendation_type: Optional[str] = None
    recommendation_text: Optional[str] = None
    recommended_actions: Optional[List[str]] = None
    related_documents: Optional[List[str]] = None
    resolution_notes: Optional[str] = None
    
    # Audit fields
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_context: Optional[Dict[str, Any]] = Field(default_factory=dict)

    class Config:
        use_enum_values = True

    @validator('user_id', 'audit_session_id', pre=True)
    def _coerce_uuid_to_str(cls, v):
        """Accept UUID objects and coerce to string for required ID fields."""
        if isinstance(v, UUID):
            return str(v)
        return v


class ComplianceGapUpdate(BaseModel):
    """Model for updating compliance gap information."""
    gap_title: Optional[str] = None
    gap_description: Optional[str] = None
    gap_category: Optional[str] = None
    risk_level: Optional[RiskLevel] = None
    business_impact: Optional[BusinessImpact] = None
    regulatory_requirement: Optional[bool] = None
    potential_fine_amount: Optional[Decimal] = None
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    resolution_notes: Optional[str] = None
    recommendation_type: Optional[str] = None
    recommendation_text: Optional[str] = None
    recommended_actions: Optional[List[str]] = None
    related_documents: Optional[List[str]] = None

    class Config:
        use_enum_values = True


class ComplianceGapFilter(BaseModel):
    """Model for filtering compliance gaps."""
    compliance_domain: Optional[str] = None
    gap_type: Optional[GapType] = None
    risk_level: Optional[RiskLevel] = None
    business_impact: Optional[BusinessImpact] = None
    status: Optional[GapStatus] = None
    assigned_to: Optional[str] = None
    user_id: Optional[str] = None
    audit_session_id: Optional[str] = None
    detection_method: Optional[DetectionMethod] = None
    regulatory_requirement: Optional[bool] = None
    is_overdue: Optional[bool] = None

    class Config:
        use_enum_values = True
