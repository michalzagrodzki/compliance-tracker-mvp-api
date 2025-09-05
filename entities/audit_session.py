"""
Audit Session entity models and validation schemas.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator

class AuditSession(BaseModel):
    """
    Audit Session entity representing a compliance audit session.
    """
    id: str
    user_id: str
    session_name: str
    compliance_domain: str
    is_active: bool
    total_queries: int
    started_at: datetime
    ended_at: Optional[datetime] = None
    session_summary: Optional[str] = None
    audit_report: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditSession":
        """Create AuditSession from dictionary data."""
        # Handle datetime parsing
        datetime_fields = ["started_at", "ended_at", "created_at", "updated_at"]
        for field in datetime_fields:
            if field in data and data[field] is not None:
                if isinstance(data[field], str):
                    # Parse ISO format datetime string
                    data[field] = datetime.fromisoformat(data[field].replace('Z', '+00:00'))
        
        # Handle missing created_at and updated_at fields for backward compatibility
        if "created_at" not in data or data["created_at"] is None:
            # Use started_at as fallback for created_at
            data["created_at"] = data.get("started_at")
        
        if "updated_at" not in data or data["updated_at"] is None:
            # Use started_at as fallback for updated_at  
            data["updated_at"] = data.get("started_at")
        
        return cls(**data)

    def to_dict(self) -> Dict[str, Any]:
        """Convert AuditSession to dictionary."""
        data = self.model_dump()
        
        # Convert datetime objects to ISO strings
        datetime_fields = ["started_at", "ended_at", "created_at", "updated_at"]
        for field in datetime_fields:
            if field in data and data[field] is not None:
                data[field] = data[field].isoformat()
        
        return data

class AuditSessionCreate(BaseModel):
    """
    Schema for creating a new audit session.
    """
    user_id: str = Field(..., description="ID of the user creating the session")
    session_name: str = Field(..., min_length=1, max_length=200, description="Name for the audit session")
    compliance_domain: str = Field(..., min_length=1, max_length=50, description="Compliance domain for the session")
    ip_address: Optional[str] = Field(None, max_length=45, description="Client IP address")
    user_agent: Optional[str] = Field(None, max_length=500, description="Client user agent")

    @validator('session_name')
    def validate_session_name(cls, v):
        """Validate session name."""
        if not v or not v.strip():
            raise ValueError("Session name cannot be empty")
        return v.strip()

    @validator('compliance_domain')
    def validate_compliance_domain(cls, v):
        """Validate compliance domain."""
        if not v or not v.strip():
            raise ValueError("Compliance domain cannot be empty")
        return v.strip()


class AuditSessionUpdate(BaseModel):
    """
    Schema for updating an audit session.
    """
    session_name: Optional[str] = Field(None, min_length=1, max_length=200)
    session_summary: Optional[str] = Field(None, max_length=2000)
    audit_report: Optional[str] = Field(None)
    is_active: Optional[bool] = None
    ended_at: Optional[datetime] = None

    @validator('session_name')
    def validate_session_name(cls, v):
        """Validate session name if provided."""
        if v is not None and (not v or not v.strip()):
            raise ValueError("Session name cannot be empty")
        return v.strip() if v else v


class AuditSessionFilter(BaseModel):
    """
    Schema for filtering audit sessions.
    """
    user_id: Optional[str] = None
    compliance_domain: Optional[str] = None
    is_active: Optional[bool] = None
    started_after: Optional[datetime] = None
    started_before: Optional[datetime] = None
    ended_after: Optional[datetime] = None
    ended_before: Optional[datetime] = None
    session_name_contains: Optional[str] = None


class AuditSessionStatistics(BaseModel):
    """
    Schema for audit session statistics.
    """
    total_sessions: int
    active_sessions: int
    completed_sessions: int
    total_queries: int
    avg_queries_per_session: float
    sessions_by_domain: Dict[str, int]
    sessions_by_user: Dict[str, int]
    avg_session_duration_minutes: Optional[float] = None
    filters_applied: Dict[str, Any]


class AuditSessionWithPdfIngestions(AuditSession):
    """
    Extended audit session model including associated PDF ingestions.
    """
    pdf_ingestions: Optional[List[Dict[str, Any]]] = None
    pdf_ingestion_count: Optional[int] = None