"""
PdfIngestion entity models for the domain layer.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PdfIngestion(BaseModel):
    """Represents a stored PDF ingestion record."""
    id: str
    filename: str
    compliance_domain: Optional[str] = None
    document_version: Optional[str] = None
    uploaded_by: Optional[str] = None
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    original_path: Optional[str] = None
    processing_status: str = "processing"  # processing | completed | failed | deleted
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    document_tags: List[str] = Field(default_factory=list)
    total_chunks: Optional[int] = None
    ingested_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

    def to_dict(self) -> Dict[str, Any]:
        data = self.model_dump()
        # Normalize datetimes to ISO strings for Supabase
        for field in ["ingested_at", "created_at", "updated_at"]:
            if data.get(field) and isinstance(data[field], datetime):
                data[field] = data[field].isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PdfIngestion":
        # Convert datetime strings if present
        for fld in ["ingested_at", "created_at", "updated_at"]:
            v = data.get(fld)
            if isinstance(v, str):
                try:
                    data[fld] = datetime.fromisoformat(v.replace('Z', '+00:00'))
                except Exception:
                    pass
        # Ensure tags/metadata structures
        if "document_tags" in data and not isinstance(data["document_tags"], list):
            data["document_tags"] = [data["document_tags"]] if data["document_tags"] else []
        if "metadata" in data and not isinstance(data["metadata"], dict):
            data["metadata"] = {}
        return cls(**data)


class PdfIngestionCreate(BaseModel):
    filename: str
    compliance_domain: Optional[str] = None
    document_version: Optional[str] = None
    uploaded_by: Optional[str] = None
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    original_path: Optional[str] = None
    processing_status: str = "processing"
    metadata: Dict[str, Any] = Field(default_factory=dict)
    document_tags: List[str] = Field(default_factory=list)


class PdfIngestionUpdate(BaseModel):
    processing_status: Optional[str] = None
    error_message: Optional[str] = None
    total_chunks: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None
    compliance_domain: Optional[str] = None
    document_version: Optional[str] = None
    document_tags: Optional[List[str]] = None


class PdfIngestionFilter(BaseModel):
    compliance_domain: Optional[str] = None
    uploaded_by: Optional[str] = None
    document_version: Optional[str] = None
    processing_status: Optional[str] = None
    filename_search: Optional[str] = None
    ingested_after: Optional[datetime] = None
    ingested_before: Optional[datetime] = None
    document_tags: Optional[List[str]] = None
    tags_match_mode: str = "any"  # any | all | exact

