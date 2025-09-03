"""
Audit Report repository implementation using Supabase.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from repositories.base import SupabaseRepository
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException,
)
from common.logging import get_logger

logger = get_logger("audit_report_repository")


class AuditReportRepository(SupabaseRepository[Dict[str, Any]]):
    """
    Repository for Audit Report operations using Supabase.
    Uses dict-based payloads to avoid introducing a new entity type.
    """

    def __init__(self, supabase_client, table_name: str = "audit_reports"):
        super().__init__(supabase_client, table_name)

    async def create(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new audit report."""
        try:
            now = datetime.now(timezone.utc).isoformat()
            defaults = {
                "report_generated_at": now,
                "created_at": now,
                "updated_at": now,
                "last_modified_at": now,
                "report_status": report_data.get("report_status") or "draft",
                "auto_generated": report_data.get("auto_generated", False),
                "notification_sent": report_data.get("notification_sent", False),
                "external_auditor_access": report_data.get("external_auditor_access", False),
                "regulatory_response_received": report_data.get("regulatory_response_received", False),
                "chat_history_ids": report_data.get("chat_history_ids", []),
                "compliance_gap_ids": report_data.get("compliance_gap_ids", []),
                "document_ids": report_data.get("document_ids", []),
                "pdf_ingestion_ids": report_data.get("pdf_ingestion_ids", []),
                "detailed_findings": report_data.get("detailed_findings", {}),
                "recommendations": report_data.get("recommendations", ""),
                "action_items": report_data.get("action_items", ""),
                "appendices": report_data.get("appendices", {}),
                "distributed_to": report_data.get("distributed_to", []),
                "audit_trail": report_data.get("audit_trail", []),
                "export_formats": report_data.get("export_formats", ["pdf"]),
                "benchmark_comparison": report_data.get("benchmark_comparison", {}),
                "integration_exports": report_data.get("integration_exports", {}),
            }
            payload = {**defaults, **report_data}

            result = self.supabase.table(self.table_name).insert(payload).execute()

            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to create audit report",
                    error_code="AUDIT_REPORT_CREATION_FAILED",
                )

            return result.data[0]
        except BusinessLogicException:
            raise
        except Exception as e:
            logger.error(f"Failed to create audit report: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create audit report",
                error_code="AUDIT_REPORT_CREATION_FAILED",
            )

    async def get_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an audit report by ID."""
        try:
            result = (
                self.supabase.table(self.table_name)
                .select("*")
                .eq("id", report_id)
                .execute()
            )

            if not result.data:
                return None

            return result.data[0]
        except Exception as e:
            logger.error(f"Failed to get audit report {report_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit report",
                error_code="AUDIT_REPORT_RETRIEVAL_FAILED",
                context={"report_id": report_id},
            )

    async def update(self, report_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Update an audit report by ID."""
        try:
            if not await self.exists(report_id):
                raise ResourceNotFoundException(
                    resource_type="AuditReport", resource_id=report_id
                )

            if not update_data:
                return await self.get_by_id(report_id)

            now = datetime.now(timezone.utc).isoformat()
            patch = {**update_data, "updated_at": now, "last_modified_at": now}

            result = (
                self.supabase.table(self.table_name)
                .update(patch)
                .eq("id", report_id)
                .execute()
            )

            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to update audit report",
                    error_code="AUDIT_REPORT_UPDATE_FAILED",
                )

            return result.data[0]
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception as e:
            logger.error(f"Failed to update audit report {report_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update audit report",
                error_code="AUDIT_REPORT_UPDATE_FAILED",
                context={"report_id": report_id},
            )

    async def get_by_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        try:
            result = (
                self.supabase.table(self.table_name)
                .select("*")
                .in_("compliance_domain", domains)
                .order("report_generated_at", desc=True)
                .execute()
            )
            return result.data
        except Exception as e:
            logger.error("Failed to list audit reports by domains", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit reports by domains",
                error_code="AUDIT_REPORT_LIST_BY_DOMAINS_FAILED",
            )

