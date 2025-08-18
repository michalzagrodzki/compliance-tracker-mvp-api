"""
Chat history entity models for the domain layer.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ChatHistoryItem(BaseModel):
    """Represents a single chat history record."""
    id: int
    conversation_id: str
    question: str
    answer: str
    created_at: datetime

    # Optional metadata columns
    audit_session_id: Optional[str] = None
    compliance_domain: Optional[str] = None
    source_document_ids: List[str] = Field(default_factory=list)
    match_threshold: Optional[float] = None
    match_count: Optional[int] = None
    user_id: Optional[str] = None
    response_time_ms: Optional[int] = None
    total_tokens_used: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        if isinstance(d.get("created_at"), datetime):
            d["created_at"] = d["created_at"].isoformat()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChatHistoryItem":
        # Normalize datatypes
        if data.get("source_document_ids") and not isinstance(data["source_document_ids"], list):
            data["source_document_ids"] = [str(data["source_document_ids"])]

        # Coerce numeric types
        if data.get("match_threshold") is not None:
            try:
                data["match_threshold"] = float(data["match_threshold"])
            except Exception:
                data["match_threshold"] = None

        return cls(**data)


class ChatHistoryCreate(BaseModel):
    conversation_id: str
    question: str
    answer: str
    audit_session_id: Optional[str] = None
    compliance_domain: Optional[str] = None
    source_document_ids: List[str] = Field(default_factory=list)
    match_threshold: Optional[float] = None
    match_count: Optional[int] = None
    user_id: Optional[str] = None
    response_time_ms: Optional[int] = None
    total_tokens_used: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ChatHistoryFilter(BaseModel):
    conversation_id: Optional[str] = None
    audit_session_id: Optional[str] = None
    compliance_domain: Optional[str] = None
    user_id: Optional[str] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None

