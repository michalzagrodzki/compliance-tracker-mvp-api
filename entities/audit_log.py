"""
Audit Log entity models and related classes.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field, validator
import uuid


class AuditLog(BaseModel):
    """
    Audit Log entity model.
    """
    
    id: str = Field(..., description="Unique identifier for the audit log entry")
    object_type: str = Field(..., description="Type of the object being audited")
    object_id: str = Field(..., description="ID of the object being audited")
    action: str = Field(..., description="Action performed on the object")
    user_id: str = Field(..., description="ID of the user who performed the action")
    audit_session_id: Optional[str] = Field(None, description="Associated audit session ID")
    compliance_domain: Optional[str] = Field(None, description="Compliance domain")
    performed_at: Optional[datetime] = Field(None, description="When the action was performed")
    ip_address: Optional[str] = Field(None, description="IP address of the user")
    user_agent: Optional[str] = Field(None, description="User agent string")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details about the action")
    risk_level: Optional[str] = Field(None, description="Risk level of the action")
    tags: List[str] = Field(default_factory=list, description="Tags associated with the audit log entry")
    
    @validator('details')
    def validate_details(cls, v):
        """Ensure details is a valid dictionary."""
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("Details must be a JSON object (dictionary)")
        return v
    
    @validator('tags')
    def validate_tags(cls, v):
        """Ensure tags is a valid list."""
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("Tags must be a list")
        return v
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditLog':
        """Create AuditLog instance from dictionary data."""
        # Convert timestamp strings to datetime objects if needed
        if isinstance(data.get('performed_at'), str):
            try:
                data['performed_at'] = datetime.fromisoformat(data['performed_at'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                data['performed_at'] = None
        
        return cls(**data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert AuditLog instance to dictionary."""
        data = self.dict()
        
        # Convert datetime objects to ISO format strings
        if data.get('performed_at'):
            data['performed_at'] = data['performed_at'].isoformat()
            
        return data


class AuditLogCreate(BaseModel):
    """
    Model for creating a new audit log entry.
    """
    
    object_type: str = Field(..., description="Type of the object being audited")
    object_id: str = Field(..., description="ID of the object being audited")
    action: str = Field(..., description="Action performed on the object")
    user_id: str = Field(..., description="ID of the user who performed the action")
    audit_session_id: Optional[str] = Field(None, description="Associated audit session ID")
    compliance_domain: Optional[str] = Field(None, description="Compliance domain")
    ip_address: Optional[str] = Field(None, description="IP address of the user")
    user_agent: Optional[str] = Field(None, description="User agent string")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details about the action")
    risk_level: Optional[str] = Field(None, description="Risk level of the action")
    tags: List[str] = Field(default_factory=list, description="Tags associated with the audit log entry")
    
    @validator('details')
    def validate_details(cls, v):
        """Ensure details is a valid dictionary."""
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("Details must be a JSON object (dictionary)")
        return v
    
    @validator('tags')
    def validate_tags(cls, v):
        """Ensure tags is a valid list."""
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("Tags must be a list")
        return v


class AuditLogFilter(BaseModel):
    """
    Model for filtering audit log entries.
    """
    
    object_type: Optional[str] = Field(None, description="Filter by object type")
    object_id: Optional[str] = Field(None, description="Filter by object ID")
    action: Optional[str] = Field(None, description="Filter by action")
    user_id: Optional[str] = Field(None, description="Filter by user ID")
    audit_session_id: Optional[str] = Field(None, description="Filter by audit session ID")
    compliance_domain: Optional[str] = Field(None, description="Filter by compliance domain")
    risk_level: Optional[str] = Field(None, description="Filter by risk level")
    performed_after: Optional[datetime] = Field(None, description="Filter by performed date (after)")
    performed_before: Optional[datetime] = Field(None, description="Filter by performed date (before)")
    ip_address: Optional[str] = Field(None, description="Filter by IP address")
    tags: Optional[List[str]] = Field(None, description="Filter by tags")
    tags_match_mode: Optional[str] = Field("any", description="Tag matching mode: 'any', 'all', or 'exact'")


class AuditLogStatistics(BaseModel):
    """
    Model for audit log statistics.
    """
    
    total_entries: int = Field(0, description="Total number of audit log entries")
    unique_users: int = Field(0, description="Number of unique users")
    unique_objects: int = Field(0, description="Number of unique objects")
    actions_breakdown: Dict[str, int] = Field(default_factory=dict, description="Breakdown by action type")
    object_types_breakdown: Dict[str, int] = Field(default_factory=dict, description="Breakdown by object type")
    risk_levels_breakdown: Dict[str, int] = Field(default_factory=dict, description="Breakdown by risk level")
    compliance_domains_breakdown: Dict[str, int] = Field(default_factory=dict, description="Breakdown by compliance domain")
    recent_activity_count: int = Field(0, description="Activity in the last 24 hours")