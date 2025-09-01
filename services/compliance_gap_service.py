"""
ComplianceGap service using Repository pattern.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from entities.compliance_gap import (
    ComplianceGap, 
    ComplianceGapCreate, 
    ComplianceGapUpdate, 
    ComplianceGapFilter,
    GapStatus,
)
from repositories.compliance_gap_repository import ComplianceGapRepository
from repositories.user_repository import UserRepository
from repositories.chat_history_repository import ChatHistoryRepository
from common.exceptions import (
    ResourceNotFoundException,
    BusinessLogicException,
)
from common.logging import get_logger

logger = get_logger("compliance_gap_service")

class ComplianceGapService:
    """
    ComplianceGap service using Repository pattern.
    Handles business logic for compliance gap management.
    """

    def __init__(
        self,
        compliance_gap_repository: ComplianceGapRepository,
        user_repository: UserRepository,
        chat_history_repository: Optional[ChatHistoryRepository] = None,
    ):
        self.gap_repository = compliance_gap_repository
        self.user_repository = user_repository
        self.chat_history_repository = chat_history_repository

    # --- New methods matching API usage ---
    async def list_compliance_gaps(
        self,
        skip: int = 0,
        limit: int = 10,
        compliance_domain: Optional[str] = None,
        gap_type: Optional[str] = None,
        risk_level: Optional[str] = None,
        status: Optional[str] = None,
        assigned_to: Optional[str] = None,
        user_id: Optional[str] = None,
        audit_session_id: Optional[str] = None,
        detection_method: Optional[str] = None,
        regulatory_requirement: Optional[bool] = None,
    ) -> List[ComplianceGap]:
        filters = ComplianceGapFilter(
            compliance_domain=compliance_domain,
            gap_type=gap_type,
            risk_level=risk_level,
            status=status,
            assigned_to=assigned_to,
            user_id=user_id,
            audit_session_id=audit_session_id,
            detection_method=detection_method,
            regulatory_requirement=regulatory_requirement,
        )
        return await self.gap_repository.list(skip=skip, limit=limit, filters=filters)

    async def list_compliance_gaps_by_compliance_domains(
        self, compliance_domains: List[str], skip: int = 0, limit: int = 50
    ) -> List[ComplianceGap]:
        return await self.gap_repository.get_by_domains(compliance_domains, skip, limit)

    async def get_compliance_gap_by_id(self, gap_id: str) -> ComplianceGap:
        gap = await self.gap_repository.get_by_id(gap_id)
        if not gap:
            raise ResourceNotFoundException(resource_type="ComplianceGap", resource_id=gap_id)
        return gap

    async def create_compliance_gap(self, payload: Dict[str, Any]) -> ComplianceGap:
        data = dict(payload)
        now_iso = datetime.now(timezone.utc).isoformat()
        data.setdefault("detected_at", now_iso)
        data.setdefault("created_at", now_iso)
        data.setdefault("updated_at", now_iso)
        # chat history enrichment
        if data.get("creation_method") == "from_chat_history":
            chat_id = data.get("chat_history_id")
            try:
                chat_id_int = int(chat_id) if chat_id is not None else None
            except Exception:
                chat_id_int = None
            if not chat_id_int:
                raise BusinessLogicException(
                    detail="chat_history_id is required when creation_method is from_chat_history",
                    error_code="COMPLIANCE_GAP_CREATE_INVALID",
                )
            if not self.chat_history_repository:
                raise BusinessLogicException(
                    detail="Chat history repository not configured",
                    error_code="SERVICE_CONFIGURATION_ERROR",
                )
            chat = await self.chat_history_repository.get_by_id(chat_id_int)
            if not chat:
                raise BusinessLogicException(
                    detail="Invalid chat_history_id: source not found",
                    error_code="COMPLIANCE_GAP_CREATE_INVALID",
                )
            data.setdefault("original_question", getattr(chat, "question", None))
            data.setdefault("audit_session_id", getattr(chat, "audit_session_id", None))
            data.setdefault("compliance_domain", getattr(chat, "compliance_domain", None))
            data.setdefault("user_id", getattr(chat, "user_id", None))
            data.setdefault("related_documents", getattr(chat, "source_document_ids", []) or [])
            if data.get("similarity_threshold_used") is None and getattr(chat, "match_threshold", None) is not None:
                data["similarity_threshold_used"] = getattr(chat, "match_threshold")
            data.pop("creation_method", None)
        create_model = ComplianceGapCreate(**{k: v for k, v in data.items() if v is not None})
        return await self.gap_repository.create(create_model)

    async def update_compliance_gap(self, gap_id: str, update_data: Dict[str, Any]) -> ComplianceGap:
        update_model = ComplianceGapUpdate(**{k: v for k, v in update_data.items() if v is not None})
        updated = await self.gap_repository.update(gap_id, update_model)
        if not updated:
            raise ResourceNotFoundException(resource_type="ComplianceGap", resource_id=gap_id)
        return updated

    async def update_gap_status(self, gap_id: str, new_status: str, resolution_notes: Optional[str] = None) -> ComplianceGap:
        status_enum = GapStatus(new_status)
        updated = await self.gap_repository.update_status(gap_id, status_enum, user_id="", notes=resolution_notes)
        if not updated:
            raise ResourceNotFoundException(resource_type="ComplianceGap", resource_id=gap_id)
        return updated

    async def mark_gap_reviewed(self, gap_id: str) -> ComplianceGap:
        updated = await self.gap_repository.mark_reviewed(gap_id, reviewer_user_id="")
        if not updated:
            raise ResourceNotFoundException(resource_type="ComplianceGap", resource_id=gap_id)
        return updated

    async def get_gaps_by_audit_session(self, audit_session_id: str) -> List[ComplianceGap]:
        return await self.gap_repository.get_by_audit_session(audit_session_id)

# Factory function
def create_compliance_gap_service(
    compliance_gap_repository: ComplianceGapRepository,
    user_repository: UserRepository,
    chat_history_repository: Optional[ChatHistoryRepository] = None,
) -> ComplianceGapService:
    """Factory function to create ComplianceGapService instance."""
    return ComplianceGapService(
        compliance_gap_repository,
        user_repository,
        chat_history_repository,
    )
