"""
Chat history service using Repository pattern.
"""

from typing import List, Optional

from entities.chat_history import ChatHistoryItem, ChatHistoryCreate, ChatHistoryFilter
from repositories.chat_history_repository import ChatHistoryRepository
from common.exceptions import ValidationException, ResourceNotFoundException


class ChatHistoryService:
    def __init__(self, repo: ChatHistoryRepository):
        self.repo = repo

    async def create(self, create: ChatHistoryCreate) -> ChatHistoryItem:
        if not create.conversation_id or not create.question or not create.answer:
            raise ValidationException(detail="conversation_id, question and answer are required")
        return await self.repo.create(create)

    async def get_by_id(self, item_id: int) -> ChatHistoryItem:
        item = await self.repo.get_by_id(item_id)
        if not item:
            raise ResourceNotFoundException(resource_type="ChatHistory", resource_id=str(item_id))
        return item

    async def list(self, skip: int = 0, limit: int = 50, filters: Optional[ChatHistoryFilter] = None) -> List[ChatHistoryItem]:
        return await self.repo.list(skip=skip, limit=limit, filters=filters)

    async def count(self, filters: Optional[ChatHistoryFilter] = None) -> int:
        return await self.repo.count(filters)

    async def list_by_conversation(self, conversation_id: str, limit: Optional[int] = None) -> List[ChatHistoryItem]:
        return await self.repo.list_by_conversation(conversation_id, limit=limit)

    async def list_by_audit_session(self, audit_session_id: str, compliance_domain: Optional[str] = None) -> List[ChatHistoryItem]:
        return await self.repo.list_by_audit_session(audit_session_id, compliance_domain)

    async def list_by_domain(self, domain: str, audit_session_id: Optional[str] = None, user_id: Optional[str] = None, skip: int = 0, limit: int = 100) -> List[ChatHistoryItem]:
        return await self.repo.list_by_domain(domain, audit_session_id, user_id, skip=skip, limit=limit)

    async def list_by_user(self, user_id: str, compliance_domain: Optional[str] = None, audit_session_id: Optional[str] = None, skip: int = 0, limit: int = 100) -> List[ChatHistoryItem]:
        return await self.repo.list_by_user(user_id, compliance_domain, audit_session_id, skip=skip, limit=limit)


def create_chat_history_service(repo: ChatHistoryRepository) -> ChatHistoryService:
    return ChatHistoryService(repo)

