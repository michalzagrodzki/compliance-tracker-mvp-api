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
                "recommendations": report_data.get("recommendations", []),
                "action_items": report_data.get("action_items", []),
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

    async def delete(self, report_id: str, soft_delete: bool = True) -> bool:
        """Delete an audit report by ID (soft by default)."""
        try:
            # Ensure it exists first
            existing = await self.get_by_id(report_id)
            if not existing:
                raise ResourceNotFoundException(
                    resource_type="AuditReport", resource_id=report_id
                )

            if soft_delete:
                now = datetime.now(timezone.utc).isoformat()
                patch = {
                    "report_status": "archived",
                    "updated_at": now,
                    "last_modified_at": now,
                }
                result = (
                    self.supabase.table(self.table_name)
                    .update(patch)
                    .eq("id", report_id)
                    .execute()
                )
                return bool(result.data)
            else:
                result = (
                    self.supabase.table(self.table_name)
                    .delete()
                    .eq("id", report_id)
                    .execute()
                )
                return bool(result.data)
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Failed to delete audit report {report_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to delete audit report",
                error_code="AUDIT_REPORT_DELETION_FAILED",
                context={"report_id": report_id},
            )

    async def list(
        self,
        skip: int = 0,
        limit: int = 10,
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[str] = "-report_generated_at",
    ) -> List[Dict[str, Any]]:
        """List audit reports with optional filters and pagination."""
        try:
            query = self.supabase.table(self.table_name).select("*")

            # Convert known filter aliases
            if filters:
                filters = dict(filters)  # shallow copy
                # Map date filters
                gen_after = filters.pop("generated_after", None)
                gen_before = filters.pop("generated_before", None)
                if gen_after:
                    query = query.gte("report_generated_at", gen_after.isoformat())
                if gen_before:
                    query = query.lte("report_generated_at", gen_before.isoformat())
                query = self._build_filters(query, filters)

            query = self._apply_ordering(query, order_by)
            # Supabase Python client uses range() for pagination (inclusive indexes)
            query = query.range(skip, skip + max(0, limit) - 1)
            result = query.execute()
            return result.data
        except Exception as e:
            logger.error("Failed to list audit reports", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit reports",
                error_code="AUDIT_REPORT_LIST_FAILED",
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

    async def get_by_domain(self, domain: str) -> List[Dict[str, Any]]:
        try:
            result = (
                self.supabase.table(self.table_name)
                .select("*")
                .eq("compliance_domain", domain)
                .order("report_generated_at", desc=True)
                .execute()
            )
            return result.data
        except Exception as e:
            logger.error("Failed to list audit reports by domain", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit reports by domain",
                error_code="AUDIT_REPORT_LIST_BY_DOMAIN_FAILED",
            )

    async def get_statistics(
        self,
        compliance_domain: Optional[str] = None,
        user_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Aggregate statistics for audit reports."""
        try:
            query = self.supabase.table(self.table_name).select("*")
            if compliance_domain:
                query = query.eq("compliance_domain", compliance_domain)
            if user_id:
                query = query.eq("user_id", user_id)
            if start_date:
                query = query.gte("report_generated_at", start_date.isoformat())
            if end_date:
                query = query.lte("report_generated_at", end_date.isoformat())

            resp = query.execute()
            reports = resp.data or []

            total_reports = len(reports)
            status_counts: Dict[str, int] = {}
            type_counts: Dict[str, int] = {}
            domain_counts: Dict[str, int] = {}
            audience_counts: Dict[str, int] = {}

            total_coverage = 0.0
            total_gaps = 0
            total_remediation_cost = 0.0
            coverage_count = 0
            gaps_count = 0
            cost_count = 0

            for r in reports:
                status_counts[r.get("report_status", "unknown")] = status_counts.get(
                    r.get("report_status", "unknown"), 0
                ) + 1
                type_counts[r.get("report_type", "unknown")] = type_counts.get(
                    r.get("report_type", "unknown"), 0
                ) + 1
                domain_counts[r.get("compliance_domain", "unknown")] = domain_counts.get(
                    r.get("compliance_domain", "unknown"), 0
                ) + 1
                audience_counts[r.get("target_audience", "unknown")] = audience_counts.get(
                    r.get("target_audience", "unknown"), 0
                ) + 1

                coverage = r.get("coverage_percentage")
                if coverage is not None:
                    total_coverage += float(coverage)
                    coverage_count += 1

                gaps = r.get("total_gaps_identified", 0) or 0
                if gaps:
                    total_gaps += gaps
                    gaps_count += 1

                cost = r.get("estimated_remediation_cost")
                if cost is not None:
                    total_remediation_cost += float(cost)
                    cost_count += 1

            avg_coverage = (total_coverage / coverage_count) if coverage_count else None
            avg_gaps = (total_gaps / gaps_count) if gaps_count else None
            avg_cost = (total_remediation_cost / cost_count) if cost_count else None

            # distributions for average
            dist_resp = (
                self.supabase.table("audit_report_distributions").select("audit_report_id").execute()
            )
            total_distributions = len(dist_resp.data or [])
            avg_dists_per_report = (
                (total_distributions / total_reports) if total_reports else None
            )

            return {
                "total_reports": total_reports,
                "reports_by_status": status_counts,
                "reports_by_type": type_counts,
                "reports_by_domain": domain_counts,
                "reports_by_audience": audience_counts,
                "avg_coverage_percentage": round(avg_coverage, 2) if avg_coverage is not None else None,
                "avg_gaps_per_report": round(avg_gaps, 2) if avg_gaps is not None else None,
                "avg_remediation_cost": round(avg_cost, 2) if avg_cost is not None else None,
                "total_distributions": total_distributions,
                "avg_distributions_per_report": round(avg_dists_per_report, 2) if avg_dists_per_report is not None else None,
                "filters_applied": {
                    "compliance_domain": compliance_domain,
                    "user_id": user_id,
                    "start_date": start_date.isoformat() if start_date else None,
                    "end_date": end_date.isoformat() if end_date else None,
                },
            }
        except Exception as e:
            logger.error("Failed to compute audit report statistics", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit report statistics",
                error_code="AUDIT_REPORT_STATISTICS_FAILED",
            )

