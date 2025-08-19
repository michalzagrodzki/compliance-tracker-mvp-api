"""
Audit Report service using Repository pattern.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from repositories.audit_report_repository import AuditReportRepository
from repositories.user_repository import UserRepository
from repositories.chat_history_repository import ChatHistoryRepository
from repositories.compliance_gap_repository import ComplianceGapRepository
from repositories.audit_session_repository import AuditSessionRepository
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException,
    AuthorizationException,
)
from common.logging import get_logger, log_business_event, log_performance

from services.audit_report_versions import create_audit_report_version

logger = get_logger("audit_report_service")


class AuditReportService:
    """
    Audit Report service using Repository pattern.
    Handles business logic for audit report listing and CRUD operations.
    """

    def __init__(
        self,
        report_repository: AuditReportRepository,
        user_repository: UserRepository,
        chat_history_repository: ChatHistoryRepository,
        compliance_gap_repository: ComplianceGapRepository,
        audit_session_repository: AuditSessionRepository,
    ):
        self.report_repository = report_repository
        self.user_repository = user_repository
        self.chat_history_repository = chat_history_repository
        self.compliance_gap_repository = compliance_gap_repository
        self.audit_session_repository = audit_session_repository

    async def list_reports(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 10,
        compliance_domain: Optional[str] = None,
        report_type: Optional[str] = None,
        report_status: Optional[str] = None,
        creator_user_id: Optional[str] = None,
        audit_session_id: Optional[str] = None,
        target_audience: Optional[str] = None,
        confidentiality_level: Optional[str] = None,
        generated_after: Optional[datetime] = None,
        generated_before: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        try:
            # Validate user exists
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(detail="Invalid or inactive user", field="user_id", value=user_id)

            filters: Dict[str, Any] = {}
            if compliance_domain:
                filters["compliance_domain"] = compliance_domain
            if report_type:
                filters["report_type"] = report_type
            if report_status:
                filters["report_status"] = report_status
            if creator_user_id:
                filters["user_id"] = creator_user_id
            if audit_session_id:
                filters["audit_session_id"] = audit_session_id
            if target_audience:
                filters["target_audience"] = target_audience
            if confidentiality_level:
                filters["confidentiality_level"] = confidentiality_level
            if generated_after:
                filters["generated_after"] = generated_after
            if generated_before:
                filters["generated_before"] = generated_before

            return await self.report_repository.list(
                skip=skip, limit=limit, filters=filters, order_by="-report_generated_at"
            )
        except ValidationException:
            raise
        except Exception as e:
            logger.error("Failed to list audit reports", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit reports",
                error_code="AUDIT_REPORT_LIST_FAILED",
            )

    async def list_reports_by_domains(self, user_id: str, domains: List[str]) -> List[Dict[str, Any]]:
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(detail="Invalid or inactive user", field="user_id", value=user_id)
            return await self.report_repository.get_by_domains(domains)
        except ValidationException:
            raise
        except Exception:
            logger.error("Failed to list audit reports by domains", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit reports by domains",
                error_code="AUDIT_REPORT_LIST_BY_DOMAINS_FAILED",
            )

    async def list_reports_by_domain(self, user_id: str, domain: str) -> List[Dict[str, Any]]:
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(detail="Invalid or inactive user", field="user_id", value=user_id)
            return await self.report_repository.get_by_domain(domain)
        except ValidationException:
            raise
        except Exception:
            logger.error("Failed to list audit reports by domain", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit reports by domain",
                error_code="AUDIT_REPORT_LIST_BY_DOMAIN_FAILED",
            )

    async def get_report_by_id(self, report_id: str, user_id: str) -> Dict[str, Any]:
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(detail="Invalid user", field="user_id", value=user_id)

            report = await self.report_repository.get_by_id(report_id)
            if not report:
                raise ResourceNotFoundException(resource_type="AuditReport", resource_id=report_id)
            return report
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception:
            logger.error(f"Failed to get audit report {report_id}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit report",
                error_code="AUDIT_REPORT_RETRIEVAL_FAILED",
                context={"report_id": report_id},
            )

    async def create_report(self, report_data: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        try:
            import time
            start = time.time()
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(detail="Invalid or inactive user", field="user_id", value=user_id)

            # Non-admin users cannot create reports for other users
            if not user.is_admin() and str(report_data.get("user_id")) != str(user_id):
                report_data["user_id"] = user_id

            created = await self.report_repository.create(report_data)

            # Business event logging
            log_business_event(
                event_type="AUDIT_REPORT_CREATED",
                entity_type="audit_report",
                entity_id=created.get("id"),
                action="create",
                user_id=user_id,
                details={"title": created.get("report_title"), "domain": created.get("compliance_domain")},
            )
            log_performance(
                operation="create_audit_report",
                duration_ms=(time.time() - start) * 1000,
                success=True,
                item_count=1,
            )
            return created
        except ValidationException:
            raise
        except Exception:
            logger.error("Failed to create audit report", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create audit report",
                error_code="AUDIT_REPORT_CREATION_FAILED",
            )

    async def update_report(self, report_id: str, update_data: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(detail="Invalid or inactive user", field="user_id", value=user_id)

            updated = await self.report_repository.update(report_id, update_data)
            if not updated:
                raise ResourceNotFoundException(resource_type="AuditReport", resource_id=report_id)
            return updated
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception:
            logger.error(f"Failed to update audit report {report_id}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update audit report",
                error_code="AUDIT_REPORT_UPDATE_FAILED",
                context={"report_id": report_id},
            )

    async def delete_report(self, report_id: str, user_id: str, soft_delete: bool = True) -> bool:
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(detail="Invalid or inactive user", field="user_id", value=user_id)
            return await self.report_repository.delete(report_id, soft_delete)
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception:
            logger.error(f"Failed to delete audit report {report_id}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to delete audit report",
                error_code="AUDIT_REPORT_DELETION_FAILED",
                context={"report_id": report_id},
            )

    async def get_statistics(
        self,
        user_id: str,
        compliance_domain: Optional[str] = None,
        target_user_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(detail="Invalid or inactive user", field="user_id", value=user_id)
            # Non-admins can only view their own stats
            stats_user_id = target_user_id if user.is_admin() else user_id
            return await self.report_repository.get_statistics(
                compliance_domain=compliance_domain,
                user_id=stats_user_id,
                start_date=start_date,
                end_date=end_date,
            )
        except ValidationException:
            raise
        except Exception:
            logger.error("Failed to get audit report statistics", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit report statistics",
                error_code="AUDIT_REPORT_STATISTICS_FAILED",
            )

    async def generate_report_from_session(
        self,
        audit_session_id: str,
        user_id: str,
        report_title: str,
        report_type: str = "compliance_audit",
        **generation_options,
    ) -> Dict[str, Any]:
        """Generate a report from an audit session using repositories (no legacy dependency)."""
        try:
            # Validate user exists
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(detail="Invalid or inactive user", field="user_id", value=user_id)

            # Load session, history, and gaps
            session = await self.audit_session_repository.get_by_id(audit_session_id)
            if not session:
                raise ResourceNotFoundException(resource_type="AuditSession", resource_id=audit_session_id)

            chat_history = await self.chat_history_repository.list_by_audit_session(audit_session_id, compliance_domain=None)
            gaps = await self.compliance_gap_repository.get_by_audit_session(audit_session_id)

            # Compute aggregates
            chat_history_ids = [int(item.id) for item in chat_history]
            gap_ids = [gap.id for gap in gaps]
            total_questions = len(chat_history)
            total_tokens = sum(int(item.total_tokens_used or 0) for item in chat_history)
            response_times = [int(item.response_time_ms or 0) for item in chat_history if item.response_time_ms]
            avg_response_time = (sum(response_times) / len(response_times)) if response_times else None

            session_duration = None
            if session.started_at and session.ended_at:
                duration_delta = session.ended_at - session.started_at
                session_duration = int(duration_delta.total_seconds() / 60)

            # Risk counts and fines
            gap_risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            regulatory_gaps = 0
            total_potential_fines = 0.0
            for gap in gaps:
                rl = str(getattr(gap, "risk_level", "medium"))
                gap_risk_counts[rl] = gap_risk_counts.get(rl, 0) + 1
                if getattr(gap, "regulatory_requirement", False):
                    regulatory_gaps += 1
                fine = getattr(gap, "potential_fine_amount", None)
                if fine:
                    try:
                        total_potential_fines += float(fine)
                    except Exception:
                        pass

            # Document coverage
            document_ids = set()
            for h in chat_history:
                for did in (h.source_document_ids or []):
                    document_ids.add(did)

            # Build narrative sections
            executive_summary = self._generate_executive_summary(
                session.session_name,
                session.compliance_domain,
                len(chat_history),
                gaps,
                gap_risk_counts,
                total_potential_fines,
            )
            detailed_findings = self._generate_detailed_findings(chat_history, gaps, list(document_ids))
            recommendations = self._generate_recommendations(gaps, session.compliance_domain)
            action_items = self._generate_action_items(gaps)

            compliance_rating = self._calculate_compliance_rating(gaps, total_questions)
            risk_score = self._calculate_risk_score(gaps)

            # Create report payload
            now_iso = datetime.now(timezone.utc).isoformat()
            report_data: Dict[str, Any] = {
                "user_id": user_id,
                "audit_session_id": audit_session_id,
                "compliance_domain": session.compliance_domain,
                "report_title": report_title,
                "report_type": report_type,
                "report_status": "draft",
                "chat_history_ids": chat_history_ids,
                "compliance_gap_ids": gap_ids,
                "document_ids": list(document_ids),
                "pdf_ingestion_ids": [],
                "total_questions_asked": total_questions,
                "questions_answered_satisfactorily": max(0, total_questions - len(gaps)),
                "total_gaps_identified": len(gaps),
                "critical_gaps_count": gap_risk_counts["critical"],
                "high_risk_gaps_count": gap_risk_counts["high"],
                "medium_risk_gaps_count": gap_risk_counts["medium"],
                "low_risk_gaps_count": gap_risk_counts["low"],
                "policy_documents_referenced": len(document_ids),
                "unique_sources_count": len(document_ids),
                "session_duration_minutes": session_duration,
                "avg_response_time_ms": avg_response_time,
                "total_tokens_used": total_tokens,
                "total_similarity_searches": total_questions,
                "overall_compliance_rating": compliance_rating,
                "potential_fine_exposure": total_potential_fines,
                "regulatory_risk_score": risk_score,
                "executive_summary": executive_summary,
                "detailed_findings": detailed_findings,
                "recommendations": recommendations,
                "action_items": action_items,
                "include_technical_details": generation_options.get("include_technical_details", False),
                "include_source_citations": generation_options.get("include_source_citations", True),
                "include_confidence_scores": generation_options.get("include_confidence_scores", False),
                "target_audience": generation_options.get("target_audience", "compliance_team"),
                "confidentiality_level": generation_options.get("confidentiality_level", "internal"),
                "generated_by": user_id,
                "auto_generated": True,
                "created_at": now_iso,
                "updated_at": now_iso,
                "last_modified_at": now_iso,
                "report_generated_at": now_iso,
            }

            created = await self.report_repository.create(report_data)

            # Initial version snapshot
            create_audit_report_version(
                audit_report_id=created["id"],
                changed_by=user_id,
                change_description="Initial report generation from audit session",
                change_type="draft_update",
                report_snapshot=created,
            )

            return created
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception:
            logger.error("Failed to generate audit report from session", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to generate audit report",
                error_code="AUDIT_REPORT_GENERATION_FAILED",
            )

    # ---- Private helpers ----
    def _generate_executive_summary(
        self,
        session_name: str,
        domain: str,
        total_interactions: int,
        gaps: List[Any],
        gap_risk_counts: Dict[str, int],
        total_potential_fines: float,
    ) -> str:
        summary = f"""
        # Executive Summary

        ## Audit Overview
        This {domain} compliance audit was conducted as part of {session_name}. The audit involved {total_interactions} queries across policies and requirements.

        ## Key Findings
        - Total Compliance Gaps Identified: {len(gaps)}
        - Risk Distribution: {gap_risk_counts.get('critical',0)} Critical, {gap_risk_counts.get('high',0)} High, {gap_risk_counts.get('medium',0)} Medium, {gap_risk_counts.get('low',0)} Low
        - Potential Financial Exposure: ${total_potential_fines:,.2f} in potential fines
        - Questions Successfully Addressed: {max(0, total_interactions - len(gaps))} of {total_interactions}

        ## Compliance Status
        """.strip()

        if gap_risk_counts.get("critical", 0) > 0:
            summary += "\n⚠️ CRITICAL: Immediate attention required for critical gaps."
        elif gap_risk_counts.get("high", 0) > 0:
            summary += "\n⚡ HIGH PRIORITY: Several high-risk gaps require prompt remediation."
        elif len(gaps) > 0:
            summary += "\n✅ MANAGEABLE: Identified gaps are manageable with standard remediation."
        else:
            summary += "\n✅ EXCELLENT: No significant compliance gaps identified."

        return summary

    def _generate_detailed_findings(self, chat_history: List[Any], gaps: List[Any], document_ids: List[str]) -> Dict[str, Any]:
        coverage_areas = sorted({h.compliance_domain for h in chat_history if h.compliance_domain})
        confidence_scores = [h.metadata.get("confidence_score") for h in chat_history if isinstance(h.metadata, dict) and h.metadata.get("confidence_score") is not None]
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else None
        low_conf_count = len([s for s in confidence_scores if s is not None and s < 0.7]) if confidence_scores else 0

        critical = len([g for g in gaps if str(getattr(g, 'risk_level', 'medium')) == 'critical'])
        high = len([g for g in gaps if str(getattr(g, 'risk_level', 'medium')) == 'high'])

        return {
            "conversation_analysis": {
                "total_interactions": len(chat_history),
                "unique_documents_referenced": len(document_ids),
                "coverage_areas": coverage_areas,
                "avg_confidence_score": avg_confidence,
                "low_confidence_interactions": low_conf_count,
            },
            "gap_analysis": {
                "total_gaps": len(gaps),
                "critical_gaps_count": critical,
                "high_risk_gaps_count": high,
            },
            "document_coverage": {
                "documents_accessed": len(document_ids),
                "citation_frequency": {},
            },
            "summary": f"Analysis of {len(chat_history)} interactions identified {len(gaps)} compliance gaps across {len(coverage_areas)} domains.",
            "key_insights": [
                f"{critical} critical gaps require immediate attention" if critical else None,
                f"Average confidence {avg_confidence:.2f} suggests documentation improvements" if (avg_confidence and avg_confidence < 0.8) else None,
            ],
        }

    def _generate_recommendations(self, gaps: List[Any], domain: str) -> List[Dict[str, Any]]:
        recs: List[Dict[str, Any]] = []
        # simple grouping by gap_type
        by_type: Dict[str, List[Any]] = {}
        for g in gaps:
            gt = str(getattr(g, "gap_type", "no_evidence"))
            by_type.setdefault(gt, []).append(g)
        for gt, items in by_type.items():
            high_priority = any(str(getattr(g, "risk_level", "medium")) in ["critical", "high"] for g in items)
            recs.append({
                "title": f"Address {gt.replace('_',' ').title()}",
                "description": f"{len(items)} gaps detected related to {gt.replace('_',' ')} in {domain}",
                "priority": "high" if high_priority else "medium",
                "recommendation_type": gt,
                "action_items": [f"Remediate: {getattr(g, 'gap_title', 'Gap')}" for g in items[:3]],
                "affected_gaps": [g.id for g in items if getattr(g, 'id', None)],
            })
        return recs

    def _generate_action_items(self, gaps: List[Any]) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for g in gaps:
            items.append({
                "title": f"Resolve: {getattr(g, 'gap_title', 'Gap')}",
                "due_in_days": 30 if str(getattr(g, 'risk_level', 'medium')) in ["critical", "high"] else 60,
                "gap_id": getattr(g, 'id', None),
                "owner": getattr(g, 'assigned_to', None),
            })
        return items

    def _calculate_compliance_rating(self, gaps: List[Any], total_questions: int) -> float:
        # Base rating 100, subtract penalties by risk level
        penalties = {"critical": 15, "high": 10, "medium": 5, "low": 2}
        score = 100.0
        for g in gaps:
            rl = str(getattr(g, "risk_level", "medium"))
            score -= penalties.get(rl, 5)
        score = max(0.0, min(100.0, score))
        # Adjust slightly for coverage
        if total_questions:
            coverage_factor = min(1.0, max(0.0, (total_questions - len(gaps)) / max(1, total_questions)))
            score = score * (0.9 + 0.1 * coverage_factor)
        return round(score, 2)

    def _calculate_risk_score(self, gaps: List[Any]) -> float:
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if not gaps:
            return 0.0
        total = sum(weights.get(str(getattr(g, "risk_level", "medium")), 2) for g in gaps)
        return round((total / (len(gaps) * 4)) * 100.0, 2)


def create_audit_report_service(
    report_repository: AuditReportRepository,
    user_repository: UserRepository,
    chat_history_repository: ChatHistoryRepository,
    compliance_gap_repository: ComplianceGapRepository,
    audit_session_repository: AuditSessionRepository,
) -> AuditReportService:
    return AuditReportService(
        report_repository,
        user_repository,
        chat_history_repository,
        compliance_gap_repository,
        audit_session_repository,
    )
