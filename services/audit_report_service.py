"""
Audit Report service using Repository pattern.
"""

import json
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

            reports = await self.report_repository.list(
                skip=skip, limit=limit, filters=filters, order_by="-report_generated_at"
            )
            # Deserialize JSON fields for client consumption
            return [self._deserialize_report_fields(report) for report in reports]
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
            reports = await self.report_repository.get_by_domains(domains)
            return [self._deserialize_report_fields(report) for report in reports]
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
            reports = await self.report_repository.get_by_domain(domain)
            return [self._deserialize_report_fields(report) for report in reports]
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
            
            # Deserialize JSON strings back to Python objects for client consumption
            report = self._deserialize_report_fields(report)
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
            
            # Deserialize for return
            created = self._deserialize_report_fields(created)

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
            return self._deserialize_report_fields(updated)
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
            detailed_findings = self.generate_detailed_findings(chat_history, gaps, list(document_ids))
            recommendations_list = self.generate_recommendations(gaps, session.compliance_domain)
            recommendations = json.dumps(recommendations_list)
            action_items_list = self.generate_action_items(gaps)
            action_items = json.dumps(action_items_list)

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
            
            # Deserialize for return  
            created = self._deserialize_report_fields(created)

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

    def generate_action_items(self, gaps: List[Any]) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for g in gaps:
            items.append({
                "title": f"Resolve: {getattr(g, 'gap_title', 'Gap')}",
                "due_in_days": 30 if str(getattr(g, 'risk_level', 'medium')) in ["critical", "high"] else 60,
                "gap_id": getattr(g, 'id', None),
                "owner": getattr(g, 'assigned_to', None),
            })
        return items

    async def generate_action_items(self, audit_session_id: str) -> str:
        """Generate AI action items for audit session based on compliance gaps and chat history."""
        try:
            import time
            from openai import OpenAI
            from config.config import settings
            
            start = time.time()
            
            # Fetch compliance gaps for the audit session
            compliance_gaps = await self.compliance_gap_repository.get_by_audit_session(audit_session_id)
            if not compliance_gaps:
                logger.info(f"No compliance gaps found for audit session {audit_session_id}")
                return "No compliance gaps identified for this audit session. No action items are needed at this time."
            
            # Fetch chat history for the audit session
            chat_history = await self.chat_history_repository.list_by_audit_session(audit_session_id, compliance_domain=None)
            
            # Group data by chat_history_id and compliance_gap
            grouped_data = []
            
            # Create a mapping of chat_history_id to chat messages
            chat_mapping = {}
            for chat in chat_history:
                chat_mapping[str(chat.id)] = {
                    'question': chat.question,
                    'answer': chat.answer,
                    'compliance_domain': chat.compliance_domain,
                    'created_at': chat.created_at.isoformat() if chat.created_at else None
                }
            
            # Group compliance gaps with their related chat history
            for gap in compliance_gaps:
                gap_data = {
                    'gap_id': gap.id,
                    'gap_title': getattr(gap, 'gap_title', 'Unknown Gap'),
                    'gap_description': getattr(gap, 'gap_description', ''),
                    'risk_level': getattr(gap, 'risk_level', 'medium'),
                    'recommendation': getattr(gap, 'recommendation_text', ''),
                    'recommended_actions': getattr(gap, 'recommended_actions', []),
                    'compliance_domain': getattr(gap, 'compliance_domain', ''),
                    'regulatory_requirement': getattr(gap, 'regulatory_requirement', False),
                    'assigned_to': getattr(gap, 'assigned_to', None),
                    'chat_history': None
                }
                
                # Find related chat history if available
                chat_history_id = getattr(gap, 'chat_history_id', None)
                if chat_history_id and str(chat_history_id) in chat_mapping:
                    gap_data['chat_history'] = chat_mapping[str(chat_history_id)]
                
                grouped_data.append(gap_data)
            
            # Prepare data for OpenAI query
            system_message = """You are an expert compliance project manager specializing in creating actionable checklist items for audit remediation. 
            Based on compliance gaps and related chat conversations, create detailed action items in checklist format that teams can execute to address the gaps.
            
            Your action items should be:
            - Specific, measurable, and actionable
            - Prioritized by risk level and regulatory requirements
            - Include clear success criteria and deadlines
            - Organized in logical implementation order
            - Include both immediate and follow-up actions
            - Consider resource requirements and dependencies
            - Professional and suitable for project management
            
            Format as a markdown checklist with clear categorization and success criteria for each item."""
            
            # Build the user prompt with all gap and chat data
            user_prompt = f"""
            Create detailed action items checklist for compliance gap remediation from audit session {audit_session_id}:

            ## Compliance Gaps and Context:
            """
            
            for i, item in enumerate(grouped_data, 1):
                user_prompt += f"""
                ### Gap {i}: {item['gap_title']} (Risk: {item['risk_level'].upper()})
                **Domain:** {item['compliance_domain']}
                **Regulatory:** {'Yes' if item['regulatory_requirement'] else 'No'}
                **Assigned To:** {item['assigned_to'] or 'Unassigned'}
                **Description:** {item['gap_description']}
                **Current Recommendation:** {item['recommendation'] or 'None provided'}
                **Suggested Actions:** {', '.join(item['recommended_actions']) if item['recommended_actions'] else 'None provided'}

                """
                if item['chat_history']:
                    user_prompt += f"""**Related Chat Context:**
                    - **Question:** {item['chat_history']['question']}
                    - **Answer:** {item['chat_history']['answer'][:400]}{'...' if len(item['chat_history']['answer']) > 400 else ''}
                    - **Date:** {item['chat_history']['created_at']}

                    """

            user_prompt += f"""
            ## Summary:
            - Total Gaps: {len(compliance_gaps)}
            - Critical/High Risk Gaps: {len([g for g in compliance_gaps if getattr(g, 'risk_level', 'medium') in ['critical', 'high']])}
            - Regulatory Gaps: {len([g for g in compliance_gaps if getattr(g, 'regulatory_requirement', False)])}
            - Chat Sessions Analyzed: {len([item for item in grouped_data if item['chat_history']])}

            ## Requirements:
            Create a comprehensive action items checklist organized by:

            1. **Immediate Actions (0-30 days)** - Critical and high-risk gaps requiring urgent attention
            2. **Short-term Actions (1-3 months)** - Medium-risk gaps and foundational improvements  
            3. **Long-term Actions (3-6 months)** - Process improvements and continuous monitoring

            For each action item, include:
            - Clear, specific task description
            - Success criteria (how to know it's complete)
            - Estimated timeline
            - Resource requirements
            - Dependencies (if any)
            - Verification method

            Format as markdown checklist with:
            - [ ] Action item description
            - **Success Criteria:** Specific measurable outcomes
            - **Timeline:** X days/weeks
            - **Owner:** Role/person responsible
            - **Resources:** What's needed
            - **Verification:** How to confirm completion

            Prioritize regulatory requirements and high-risk gaps first.
            """
            
            # Call OpenAI API
            client = OpenAI(api_key=settings.openai_api_key)
            
            completion = client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=3500,
            )
            
            action_items = completion.choices[0].message.content.strip()
            
            # Log performance
            log_performance(
                operation="generate_action_items",
                duration_ms=(time.time() - start) * 1000,
                success=True,
                item_count=len(compliance_gaps),
            )
            
            logger.info(f"Successfully generated action items for audit session {audit_session_id} with {len(compliance_gaps)} gaps")
            
            # Return action items with metadata
            return {
                'action_items': action_items,
                'gaps_analyzed': len(compliance_gaps),
                'chat_sessions_analyzed': len([item for item in grouped_data if item['chat_history']]),
                'regulatory_gaps': len([g for g in compliance_gaps if getattr(g, 'regulatory_requirement', False)]),
                'critical_high_risk_gaps': len([g for g in compliance_gaps if getattr(g, 'risk_level', 'medium') in ['critical', 'high']])
            }
            
        except Exception as e:
            logger.error(f"Failed to generate action items for audit session {audit_session_id}: {str(e)}", exc_info=True)
            raise BusinessLogicException(
                detail=f"Failed to generate action items: {str(e)}",
                error_code="ACTION_ITEMS_GENERATION_FAILED",
                context={"audit_session_id": audit_session_id},
            )

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

    def _deserialize_report_fields(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Deserialize JSON string fields back to Python objects for client consumption."""
        if not report:
            return report
            
        report_copy = report.copy()
        
        # Deserialize recommendations from JSON string to list
        recommendations = report_copy.get("recommendations")
        if isinstance(recommendations, str):
            try:
                report_copy["recommendations"] = json.loads(recommendations)
            except (json.JSONDecodeError, ValueError):
                logger.warning(f"Failed to deserialize recommendations JSON: {recommendations}")
                report_copy["recommendations"] = []
        
        # Deserialize action_items from JSON string to list
        action_items = report_copy.get("action_items")
        if isinstance(action_items, str):
            try:
                report_copy["action_items"] = json.loads(action_items)
            except (json.JSONDecodeError, ValueError):
                logger.warning(f"Failed to deserialize action_items JSON: {action_items}")
                report_copy["action_items"] = []
        
        return report_copy

    async def generate_recommendations(self, audit_session_id: str) -> str:
        """Generate AI recommendations for audit session based on compliance gaps and chat history."""
        try:
            import time
            from openai import OpenAI
            from config.config import settings
            
            start = time.time()
            
            # Fetch compliance gaps for the audit session
            compliance_gaps = await self.compliance_gap_repository.get_by_audit_session(audit_session_id)
            if not compliance_gaps:
                logger.info(f"No compliance gaps found for audit session {audit_session_id}")
                return "No compliance gaps identified for this audit session. No specific recommendations are needed at this time."
            
            # Fetch chat history for the audit session
            chat_history = await self.chat_history_repository.list_by_audit_session(audit_session_id, compliance_domain=None)
            
            # Group data by chat_history_id and compliance_gap
            grouped_data = []
            
            # Create a mapping of chat_history_id to chat messages
            chat_mapping = {}
            for chat in chat_history:
                chat_mapping[str(chat.id)] = {
                    'question': chat.question,
                    'answer': chat.answer,
                    'compliance_domain': chat.compliance_domain,
                    'created_at': chat.created_at.isoformat() if chat.created_at else None
                }
            
            # Group compliance gaps with their related chat history
            for gap in compliance_gaps:
                gap_data = {
                    'gap_id': gap.id,
                    'gap_title': getattr(gap, 'gap_title', 'Unknown Gap'),
                    'gap_description': getattr(gap, 'gap_description', ''),
                    'risk_level': getattr(gap, 'risk_level', 'medium'),
                    'recommendation': getattr(gap, 'recommendation_text', ''),
                    'compliance_domain': getattr(gap, 'compliance_domain', ''),
                    'chat_history': None
                }
                
                # Find related chat history if available
                chat_history_id = getattr(gap, 'chat_history_id', None)
                if chat_history_id and str(chat_history_id) in chat_mapping:
                    gap_data['chat_history'] = chat_mapping[str(chat_history_id)]
                
                grouped_data.append(gap_data)
            
            # Prepare data for OpenAI query
            system_message = """You are an expert compliance analyst specializing in generating actionable recommendations for audit reports. 
            Based on compliance gaps identified during an audit session and the related chat conversations, provide comprehensive, 
            practical recommendations that address the specific gaps and improve overall compliance posture.
            
            Your recommendations should be:
            - Specific and actionable
            - Prioritized by risk level
            - Grouped by compliance domain when applicable
            - Include both immediate and long-term actions
            - Consider the context from chat conversations
            - Professional and suitable for audit report inclusion"""
            
            # Build the user prompt with all gap and chat data
            user_prompt = f"""
            Analyze the following compliance gaps and related chat history from audit session {audit_session_id} and generate comprehensive recommendations:

            ## Compliance Gaps and Related Context:
            """
            
            for i, item in enumerate(grouped_data, 1):
                user_prompt += f"""
                ### Gap {i}: {item['gap_title']} (Risk: {item['risk_level'].upper()})
                **Domain:** {item['compliance_domain']}
                **Description:** {item['gap_description']}
                **Existing Recommendation:** {item['recommendation'] or 'None provided'}

                """
                if item['chat_history']:
                    user_prompt += f"""**Related Chat Context:**
                    - **Question:** {item['chat_history']['question']}
                    - **Answer:** {item['chat_history']['answer'][:500]}{'...' if len(item['chat_history']['answer']) > 500 else ''}
                    - **Date:** {item['chat_history']['created_at']}

                    """

            user_prompt += f"""
            ## Summary:
            - Total Gaps: {len(compliance_gaps)}
            - High/Critical Risk Gaps: {len([g for g in compliance_gaps if getattr(g, 'risk_level', 'medium') in ['high', 'critical']])}
            - Chat Sessions Analyzed: {len([item for item in grouped_data if item['chat_history']])}

            ## Requirements:
            Generate a comprehensive recommendations report that:
            1. **Executive Summary** - Overview of key recommendations
            2. **Priority Actions** - Immediate actions for high/critical risk gaps
            3. **Implementation Roadmap** - Medium-term actions with timeline
            4. **Process Improvements** - Long-term systematic improvements
            5. **Monitoring & Follow-up** - How to track progress and ensure compliance

            Format the response in clear markdown suitable for inclusion in an audit report.
            """
            
            # Call OpenAI API
            client = OpenAI(api_key=settings.openai_api_key)
            
            completion = client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=3000,
            )
            
            recommendations = completion.choices[0].message.content.strip()
            
            # Log performance
            log_performance(
                operation="generate_recommendations",
                duration_ms=(time.time() - start) * 1000,
                success=True,
                item_count=len(compliance_gaps),
            )
            
            logger.info(f"Successfully generated recommendations for audit session {audit_session_id} with {len(compliance_gaps)} gaps")
            
            # Return recommendations with metadata
            return {
                'recommendations': recommendations,
                'gaps_analyzed': len(compliance_gaps),
                'chat_sessions_analyzed': len([item for item in grouped_data if item['chat_history']]),
                'high_risk_gaps': len([g for g in compliance_gaps if getattr(g, 'risk_level', 'medium') in ['high', 'critical']])
            }
            
        except Exception as e:
            logger.error(f"Failed to generate recommendations for audit session {audit_session_id}: {str(e)}", exc_info=True)
            raise BusinessLogicException(
                detail=f"Failed to generate recommendations: {str(e)}",
                error_code="RECOMMENDATIONS_GENERATION_FAILED",
                context={"audit_session_id": audit_session_id},
            )


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
