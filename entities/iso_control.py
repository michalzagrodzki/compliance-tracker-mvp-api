"""
ISO Control entity models and related classes.
"""

from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator


class ISOControl(BaseModel):
    """
    ISO Control entity model.
    """
    
    id: str = Field(..., description="Unique identifier for the ISO control")
    name: str = Field(..., min_length=1, max_length=50, description="ISO control name")
    controls: Dict[str, Any] = Field(default_factory=dict, description="JSON object containing control details")
    created_at: Optional[datetime] = Field(None, description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    
    @validator('name')
    def validate_name(cls, v):
        """Validate and clean the name field."""
        if v:
            return v.strip()
        return v
    
    @validator('controls')
    def validate_controls(cls, v):
        """Ensure controls is a valid dictionary."""
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("Controls must be a JSON object (dictionary)")
        return v
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ISOControl':
        """Create ISOControl instance from dictionary data."""
        # Convert timestamp strings to datetime objects if needed
        if isinstance(data.get('created_at'), str):
            try:
                data['created_at'] = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                data['created_at'] = None
                
        if isinstance(data.get('updated_at'), str):
            try:
                data['updated_at'] = datetime.fromisoformat(data['updated_at'].replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                data['updated_at'] = None
        
        return cls(**data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert ISOControl instance to dictionary."""
        data = self.dict()
        
        # Convert datetime objects to ISO format strings
        if data.get('created_at'):
            data['created_at'] = data['created_at'].isoformat()
        if data.get('updated_at'):
            data['updated_at'] = data['updated_at'].isoformat()
            
        return data


class ISOControlCreate(BaseModel):
    """
    Model for creating a new ISO control.
    """
    
    name: str = Field(..., min_length=1, max_length=50, description="ISO control name")
    controls: Dict[str, Any] = Field(default_factory=dict, description="JSON object containing control details")
    
    @validator('name')
    def validate_name(cls, v):
        """Validate and clean the name field."""
        if v:
            return v.strip()
        return v
    
    @validator('controls')
    def validate_controls(cls, v):
        """Ensure controls is a valid dictionary."""
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("Controls must be a JSON object (dictionary)")
        return v


class ISOControlUpdate(BaseModel):
    """
    Model for updating an ISO control.
    """
    
    name: Optional[str] = Field(None, min_length=1, max_length=50, description="ISO control name")
    controls: Optional[Dict[str, Any]] = Field(None, description="JSON object containing control details")
    
    @validator('name')
    def validate_name(cls, v):
        """Validate and clean the name field."""
        if v:
            return v.strip()
        return v
    
    @validator('controls')
    def validate_controls(cls, v):
        """Ensure controls is a valid dictionary."""
        if v is None:
            return None
        if not isinstance(v, dict):
            raise ValueError("Controls must be a JSON object (dictionary)")
        return v


class ISOControlFilter(BaseModel):
    """
    Model for filtering ISO controls.
    """
    
    name: Optional[str] = Field(None, description="Filter by control name (partial match)")
    created_after: Optional[datetime] = Field(None, description="Filter by creation date (after)")
    created_before: Optional[datetime] = Field(None, description="Filter by creation date (before)")
    updated_after: Optional[datetime] = Field(None, description="Filter by update date (after)")
    updated_before: Optional[datetime] = Field(None, description="Filter by update date (before)")