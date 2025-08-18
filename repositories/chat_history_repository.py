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

    async def create(self, item: ChatHistoryCreate) -> ChatHistoryItem:
        try:
            data = {k: v for k, v in item.model_dump().items() if v is not None}
            res = self.supabase.table(self.table_name).insert(data).execute()
            if not res.data:
                raise BusinessLogicException(detail="Failed to insert chat history", error_code="CHAT_HISTORY_CREATE_FAILED")
            return ChatHistoryItem.from_dict(res.data[0])
        except Exception as e:
            logger.error(f"Create chat history failed: {e}", exc_info=True)
            raise BusinessLogicException(detail="Failed to insert chat history", error_code="CHAT_HISTORY_CREATE_FAILED")

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
        try:
            res = self.supabase.table(self.table_name).update(update_data).eq("id", item_id).execute()
            if not res.data:
                return None
            return ChatHistoryItem.from_dict(res.data[0])
        except Exception as e:
            logger.error(f"Update chat history failed: {item_id}: {e}", exc_info=True)
            raise BusinessLogicException(detail="Failed to update chat history", error_code="CHAT_HISTORY_UPDATE_FAILED")

    async def delete(self, item_id: int) -> bool:
        try:
            res = self.supabase.table(self.table_name).delete().eq("id", item_id).execute()
            return bool(res.data)
        except Exception as e:
            logger.error(f"Delete chat history failed: {item_id}: {e}", exc_info=True)
            raise BusinessLogicException(detail="Failed to delete chat history", error_code="CHAT_HISTORY_DELETE_FAILED")

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

    async def list_by_conversation(self, conversation_id: str, limit: Optional[int] = None) -> List[ChatHistoryItem]:
        try:
            q = (
                self.supabase.table(self.table_name)
                .select("*")
                .eq("conversation_id", conversation_id)
                .order("created_at", desc=False)
            )
            if limit:
                q = q.limit(limit)
            res = q.execute()
            return [ChatHistoryItem.from_dict(r) for r in res.data]
        except Exception as e:
            logger.error(f"List by conversation failed: {conversation_id}: {e}")
            raise BusinessLogicException(detail="Failed to list by conversation", error_code="CHAT_HISTORY_CONVERSATION_FAILED")

    async def list_by_audit_session(self, audit_session_id: str, compliance_domain: Optional[str] = None) -> List[ChatHistoryItem]:
        try:
            q = (
                self.supabase.table(self.table_name)
                .select("*")
                .eq("audit_session_id", audit_session_id)
                .order("created_at", desc=False)
            )
            if compliance_domain:
                q = q.eq("compliance_domain", compliance_domain)
            res = q.execute()
            return [ChatHistoryItem.from_dict(r) for r in res.data]
        except Exception as e:
            logger.error(f"List by audit session failed: {audit_session_id}: {e}")
            raise BusinessLogicException(detail="Failed to list by audit session", error_code="CHAT_HISTORY_AUDITSESSION_FAILED")

    async def list_by_domain(self, domain_code: str, audit_session_id: Optional[str] = None, user_id: Optional[str] = None, skip: int = 0, limit: int = 100) -> List[ChatHistoryItem]:
        try:
            q = (
                self.supabase.table(self.table_name)
                .select("*")
                .eq("compliance_domain", domain_code)
                .order("created_at", desc=True)
                .range(skip, skip + limit - 1)
            )
            if audit_session_id:
                q = q.eq("audit_session_id", audit_session_id)
            if user_id:
                q = q.eq("user_id", user_id)
            res = q.execute()
            return [ChatHistoryItem.from_dict(r) for r in res.data]
        except Exception as e:
            logger.error(f"List by domain failed: {domain_code}: {e}")
            raise BusinessLogicException(detail="Failed to list by domain", error_code="CHAT_HISTORY_DOMAIN_FAILED")

    async def list_by_user(self, user_id: str, compliance_domain: Optional[str] = None, audit_session_id: Optional[str] = None, skip: int = 0, limit: int = 100) -> List[ChatHistoryItem]:
        try:
            q = (
                self.supabase.table(self.table_name)
                .select("*")
                .eq("user_id", user_id)
                .order("created_at", desc=True)
                .range(skip, skip + limit - 1)
            )
            if compliance_domain:
                q = q.eq("compliance_domain", compliance_domain)
            if audit_session_id:
                q = q.eq("audit_session_id", audit_session_id)
            res = q.execute()
            return [ChatHistoryItem.from_dict(r) for r in res.data]
        except Exception as e:
            logger.error(f"List by user failed: {user_id}: {e}")
            raise BusinessLogicException(detail="Failed to list by user", error_code="CHAT_HISTORY_USER_FAILED")

