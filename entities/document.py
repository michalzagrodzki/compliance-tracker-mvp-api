"""
Document entity models for the domain layer.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
import json
from pydantic import BaseModel, Field


class DocumentChunk(BaseModel):
    """Represents a chunked document record stored in the vector table."""
    id: str
    content: str
    embedding: Optional[List[float]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Domain metadata duplicated as first-class columns in the table
    compliance_domain: Optional[str] = None
    document_version: Optional[str] = None
    document_tags: List[str] = Field(default_factory=list)
    source_filename: Optional[str] = None
    source_page_number: Optional[int] = None
    chunk_index: Optional[int] = None

    approval_status: Optional[str] = None
    uploaded_by: Optional[str] = None
    approved_by: Optional[str] = None

    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        # Normalize datetimes to ISO
        for fld in ["created_at", "updated_at"]:
            v = d.get(fld)
            if isinstance(v, datetime):
                d[fld] = v.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DocumentChunk":
        # Datetime parsing
        for fld in ["created_at", "updated_at"]:
            v = data.get(fld)
            if isinstance(v, str):
                try:
                    data[fld] = datetime.fromisoformat(v.replace('Z', '+00:00'))
                except Exception:
                    pass
        # Ensure list/dict shapes
        if "document_tags" in data and not isinstance(data["document_tags"], list):
            data["document_tags"] = [data["document_tags"]] if data["document_tags"] else []
        if "metadata" in data and not isinstance(data.get("metadata"), dict):
            data["metadata"] = {}
        # Normalize embedding field: may come as JSON string from PGVector
        if "embedding" in data and data["embedding"] is not None:
            emb = data["embedding"]
            try:
                if isinstance(emb, str):
                    # Try to parse JSON-like string
                    parsed = json.loads(emb)
                    if isinstance(parsed, list):
                        emb = parsed
                    else:
                        emb = None
                if isinstance(emb, list):
                    # Ensure floats
                    emb = [float(x) for x in emb]
                else:
                    emb = None
            except Exception:
                emb = None
            data["embedding"] = emb
        return cls(**data)


class DocumentFilter(BaseModel):
    compliance_domain: Optional[str] = None
    document_version: Optional[str] = None
    source_filename: Optional[str] = None  # partial match
    document_tags: Optional[List[str]] = None
    tags_match_mode: str = "any"  # any|all|exact
    approval_status: Optional[str] = None
    uploaded_by: Optional[str] = None
    approved_by: Optional[str] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
