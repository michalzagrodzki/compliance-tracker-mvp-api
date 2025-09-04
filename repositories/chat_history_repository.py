"""
Chat history repository implementation using Supabase.
"""

from typing import Optional, List, Dict, Any

from repositories.base import SupabaseRepository
from entities.chat_history import ChatHistoryItem, ChatHistoryCreate, ChatHistoryFilter
from common.exceptions import BusinessLogicException
from common.logging import get_logger

logger = get_logger("chat_history_repository")


class ChatHistoryRepository(SupabaseRepository[ChatHistoryItem]):
    """Repository for ChatHistoryItem operations with Supabase."""

    def __init__(self, supabase_client, table_name: str = "chat_history"):
        super().__init__(supabase_client, table_name)

    async def create(self, item_create: ChatHistoryCreate) -> ChatHistoryItem:
        """Create a new chat history item."""
        try:
            data = item_create.model_dump()
            # Let DB handle created_at/id defaults if configured
            res = self.supabase.table(self.table_name).insert(data).execute()
            if not res.data:
                raise BusinessLogicException(
                    detail="Failed to create chat history",
                    error_code="CHAT_HISTORY_CREATE_FAILED",
                )
            return ChatHistoryItem.from_dict(res.data[0])
        except Exception as e:
            logger.error(f"Create chat history failed: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create chat history",
                error_code="CHAT_HISTORY_CREATE_FAILED",
            )

    async def get_by_id(self, item_id: int) -> Optional[ChatHistoryItem]:
        try:
            res = self.supabase.table(self.table_name).select("*").eq("id", item_id).limit(1).execute()
            if not res.data:
                return None
            return ChatHistoryItem.from_dict(res.data[0])
        except Exception as e:
            logger.error(f"Get chat history by id failed: {item_id}: {e}", exc_info=True)
            raise BusinessLogicException(detail="Failed to retrieve chat history", error_code="CHAT_HISTORY_GET_FAILED")

    async def update(self, item_id: int, update_data: Dict[str, Any]) -> Optional[ChatHistoryItem]:
        """Update an existing chat history item by ID."""
        try:
            update_dict = {k: v for k, v in (update_data or {}).items() if v is not None}
            if not update_dict:
                return await self.get_by_id(item_id)
            res = (
                self.supabase
                .table(self.table_name)
                .update(update_dict)
                .eq("id", item_id)
                .execute()
            )
            if not res.data:
                return None
            return ChatHistoryItem.from_dict(res.data[0])
        except Exception as e:
            logger.error(f"Update chat history failed: {item_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update chat history",
                error_code="CHAT_HISTORY_UPDATE_FAILED",
            )

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[ChatHistoryFilter] = None,
        order_by: Optional[str] = None,
    ) -> List[ChatHistoryItem]:
        try:
            q = self.supabase.table(self.table_name).select("*")

            if filters:
                simple_filters: Dict[str, Any] = {}
                if filters.conversation_id is not None:
                    simple_filters["conversation_id"] = filters.conversation_id
                if filters.audit_session_id is not None:
                    simple_filters["audit_session_id"] = filters.audit_session_id
                if filters.compliance_domain is not None:
                    simple_filters["compliance_domain"] = filters.compliance_domain
                if filters.user_id is not None:
                    simple_filters["user_id"] = filters.user_id

                q = self._build_filters(q, simple_filters)

                if filters.created_after is not None:
                    q = q.gte("created_at", filters.created_after.isoformat())
                if filters.created_before is not None:
                    q = q.lte("created_at", filters.created_before.isoformat())

            q = self._apply_ordering(q, order_by or "-created_at").range(skip, skip + limit - 1)
            res = q.execute()
            return [ChatHistoryItem.from_dict(r) for r in res.data]
        except Exception as e:
            logger.error(f"List chat history failed: {e}", exc_info=True)
            raise BusinessLogicException(detail="Failed to list chat history", error_code="CHAT_HISTORY_LIST_FAILED")

    async def count(self, filters: Optional[ChatHistoryFilter] = None) -> int:
        try:
            q = self.supabase.table(self.table_name).select("id", count="exact")
            if filters:
                simple_filters: Dict[str, Any] = {}
                if filters.conversation_id is not None:
                    simple_filters["conversation_id"] = filters.conversation_id
                if filters.audit_session_id is not None:
                    simple_filters["audit_session_id"] = filters.audit_session_id
                if filters.compliance_domain is not None:
                    simple_filters["compliance_domain"] = filters.compliance_domain
                if filters.user_id is not None:
                    simple_filters["user_id"] = filters.user_id
                q = self._build_filters(q, simple_filters)
                if filters.created_after is not None:
                    q = q.gte("created_at", filters.created_after.isoformat())
                if filters.created_before is not None:
                    q = q.lte("created_at", filters.created_before.isoformat())
            res = q.execute()
            return int(getattr(res, "count", 0) or 0)
        except Exception:
            return 0

    async def list_by_audit_session(
        self,
        audit_session_id: str,
        compliance_domain: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
        order_by: Optional[str] = None,
    ) -> List[ChatHistoryItem]:
        """List chat history records for a given audit session (optionally in a domain)."""
        try:
            q = (
                self.supabase
                .table(self.table_name)
                .select("*")
                .eq("audit_session_id", audit_session_id)
            )
            if compliance_domain:
                q = q.eq("compliance_domain", compliance_domain)
            q = self._apply_ordering(q, order_by or "-created_at").range(skip, skip + limit - 1)
            res = q.execute()
            return [ChatHistoryItem.from_dict(r) for r in (res.data or [])]
        except Exception as e:
            logger.error(f"List chat history by audit_session failed: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to list chat history by audit session",
                error_code="CHAT_HISTORY_LIST_BY_SESSION_FAILED",
            )
