"""
Chat history service using Repository pattern.
"""
from typing import List, Optional

from entities.chat_history import ChatHistoryItem, ChatHistoryFilter
from repositories.chat_history_repository import ChatHistoryRepository
from common.exceptions import ResourceNotFoundException


class ChatHistoryService:
    def __init__(self, repo: ChatHistoryRepository):
        self.repo = repo

    async def get_by_id(self, item_id: int) -> ChatHistoryItem:
        item = await self.repo.get_by_id(item_id)
        if not item:
            raise ResourceNotFoundException(resource_type="ChatHistory", resource_id=str(item_id))
        return item

    async def list(self, skip: int = 0, limit: int = 50, filters: Optional[ChatHistoryFilter] = None) -> List[ChatHistoryItem]:
        return await self.repo.list(skip=skip, limit=limit, filters=filters)

    async def count(self, filters: Optional[ChatHistoryFilter] = None) -> int:
        return await self.repo.count(filters)

def create_chat_history_service(repo: ChatHistoryRepository) -> ChatHistoryService:
    return ChatHistoryService(repo)

