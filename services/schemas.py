from pydantic import BaseModel, Field
from typing import Any, List, Dict, Optional

class UploadResponse(BaseModel):
    message: str
    inserted_count: int

class QueryRequest(BaseModel):
    question: str
    conversation_id: Optional[str] = Field(None, description="Conversation UUID")


class SourceDoc(BaseModel):
    page_content: str | None = None  # optional if not used
    metadata: Dict[str, Any]
    similarity: float | None = None
    id: str

class QueryResponse(BaseModel):
    answer: str
    source_docs: List[SourceDoc]

class ChatHistoryItem(BaseModel):
    id: int
    conversation_id: str
    question: str
    answer: str