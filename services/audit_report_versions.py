"""
Audit Report Version service.
Provides creation of versioned snapshots for audit reports.
"""

from typing import Dict, Any
from datetime import datetime, timezone
import uuid

from common.exceptions import BusinessLogicException
from common.logging import get_logger
from db.supabase_client import create_supabase_client
from config.config import settings


logger = get_logger("audit_report_version_service")


class AuditReportVersionService:
    """
    Service for managing audit report versions.
    Allows creating new versioned snapshots for a given audit report.
    """

    def __init__(self, supabase_client, table_name: str = settings.supabase_table_audit_report_versions):
        self.supabase = supabase_client
        self.table_name = table_name

    def create_version(
        self,
        audit_report_id: str,
        changed_by: str,
        change_description: str,
        change_type: str,
        report_snapshot: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create a new version entry for an audit report."""
        try:
            logger.info(f"Creating new version for audit report {audit_report_id}")

            resp = (
                self.supabase
                .table(self.table_name)
                .select("version_number")
                .eq("audit_report_id", audit_report_id)
                .order("version_number", desc=True)
                .limit(1)
                .execute()
            )

            next_version = 1
            if getattr(resp, "data", None):
                next_version = resp.data[0]["version_number"] + 1

            # Serialize UUIDs to strings before creating version
            serialized_snapshot = self._serialize_uuids(report_snapshot)

            version_data = {
                "audit_report_id": audit_report_id,
                "version_number": next_version,
                "change_description": change_description,
                "changed_by": changed_by,
                "change_type": change_type,
                "report_snapshot": serialized_snapshot,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

            insert_resp = (
                self.supabase
                .table(self.table_name)
                .insert(version_data)
                .execute()
            )

            if hasattr(insert_resp, "error") and insert_resp.error:
                logger.error("Supabase audit report version creation failed", exc_info=True)
                raise BusinessLogicException(
                    detail=f"Failed to create audit report version: {getattr(insert_resp.error, 'message', 'unknown error')}",
                    error_code="AUDIT_REPORT_VERSION_CREATION_FAILED",
                    context={"audit_report_id": audit_report_id},
                )

            if not getattr(insert_resp, "data", None):
                raise BusinessLogicException(
                    detail="Failed to create audit report version: No data returned from database",
                    error_code="AUDIT_REPORT_VERSION_CREATION_FAILED",
                    context={"audit_report_id": audit_report_id},
                )

            logger.info(
                f"Created version {next_version} for audit report {audit_report_id}"
            )
            return insert_resp.data[0]

        except BusinessLogicException:
            raise
        except Exception as e:
            logger.error(
                f"Failed to create version for audit report {audit_report_id}",
                exc_info=True,
            )
            raise BusinessLogicException(
                detail=f"Database error: {e}",
                error_code="AUDIT_REPORT_VERSION_CREATION_FAILED",
                context={"audit_report_id": audit_report_id},
            )

    def _serialize_uuids(self, obj: Any) -> Any:  # type: ignore[name-defined]
        if isinstance(obj, uuid.UUID):
            return str(obj)
        if isinstance(obj, dict):
            return {key: self._serialize_uuids(value) for key, value in obj.items()}
        if isinstance(obj, list):
            return [self._serialize_uuids(item) for item in obj]
        return obj


def create_audit_report_version_service(supabase_client) -> AuditReportVersionService:
    """Factory function to create AuditReportVersionService instance."""
    return AuditReportVersionService(supabase_client)


# Backward-compatible functional wrapper (optional for existing callers)
def create_audit_report_version(
    audit_report_id: str,
    changed_by: str,
    change_description: str,
    change_type: str,
    report_snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    service = create_audit_report_version_service(create_supabase_client())
    return service.create_version(
        audit_report_id,
        changed_by,
        change_description,
        change_type,
        report_snapshot,
    )
