"""
ComplianceRecommendationService for generating AI-powered compliance recommendations.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from entities.compliance_gap import ComplianceGap, RiskLevel
from repositories.compliance_gap_repository import ComplianceGapRepository
from repositories.user_repository import UserRepository
from repositories.chat_history_repository import ChatHistoryRepository
from services.ai_service import AIService
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException,
    AuthorizationException
)
from common.logging import get_logger, log_business_event, log_performance

logger = get_logger("compliance_recommendation_service")


class ComplianceRecommendationService:
    """
    Service for generating AI-powered compliance recommendations.
    Integrates with compliance gap data to provide contextual recommendations.
    """

    def __init__(
        self, 
        ai_service: AIService, 
        compliance_gap_repository: ComplianceGapRepository,
        user_repository: UserRepository,
        chat_history_repository: Optional[ChatHistoryRepository] = None,
    ):
        self.ai_service = ai_service
        self.gap_repository = compliance_gap_repository
        self.user_repository = user_repository
        self.chat_history_repository = chat_history_repository

    async def generate_gap_recommendation(
        self,
        gap_id: str,
        user_id: str,
        recommendation_type: str = "comprehensive",
        include_implementation_plan: bool = True,
        include_citations: bool = True,
        max_chat_docs: int = 5,
    ) -> Dict[str, Any]:
        try:
            import time, json
            start_time = time.time()

            # Validate user and get gap with access control
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive user",
                    field="user_id",
                    value=user_id
                )

            gap = await self.gap_repository.get_by_id(gap_id)
            if not gap:
                raise ResourceNotFoundException(
                    resource_type="ComplianceGap",
                    resource_id=gap_id
                )

            if not (user.is_admin() or user.can_access_domain(gap.compliance_domain)):
                raise AuthorizationException(
                    detail=f"Access denied to compliance domain: {gap.compliance_domain}",
                    error_code="DOMAIN_ACCESS_DENIED"
                )

            # Attempt to enrich with chat history context
            chat_item = None
            chat_citations: List[Dict[str, Any]] = []
            source_document_ids: List[str] = []
            question: Optional[str] = None
            prior_answer: Optional[str] = None

            if getattr(gap, "chat_history_id", None) and self.chat_history_repository:
                try:
                    chat_id_int = int(str(gap.chat_history_id))
                    chat_item = await self.chat_history_repository.get_by_id(chat_id_int)
                except Exception:
                    chat_item = None

            if chat_item:
                question = getattr(chat_item, "question", None)
                prior_answer = getattr(chat_item, "answer", None)
                source_document_ids = list(getattr(chat_item, "source_document_ids", []) or [])

                # Metadata may be dict or JSON string; normalize to dict
                raw_meta = getattr(chat_item, "metadata", {})
                if isinstance(raw_meta, str):
                    try:
                        raw_meta = json.loads(raw_meta)
                    except Exception:
                        raw_meta = {}

                doc_details = []
                try:
                    doc_details = list(raw_meta.get("document_details", []) or [])
                except Exception:
                    doc_details = []

                # Build top-N citations list
                if doc_details:
                    for i, d in enumerate(doc_details[: max(1, max_chat_docs) ]):
                        chat_citations.append({
                            "index": i + 1,
                            "title": d.get("title"),
                            "source_filename": d.get("source_filename"),
                            "source_page_number": d.get("source_page_number"),
                            "similarity": d.get("similarity"),
                            "document_id": d.get("document_id"),
                            "document_tags": d.get("document_tags"),
                        })

            # Build improved recommendation prompt (with optional chat/doc context)
            prompt = self._build_recommendation_prompt_v2(
                gap=gap,
                recommendation_type=recommendation_type,
                include_implementation_plan=include_implementation_plan,
                question=question,
                prior_answer=prior_answer,
                citations=chat_citations if include_citations else [],
                source_document_ids=source_document_ids,
            )

            response_schema = self._get_recommendation_schema(include_implementation_plan)

            ai_context = {
                "role": "compliance expert and consultant",
                "domain": gap.compliance_domain,
                "instructions": (
                    "Provide practical, actionable, and evidence-grounded recommendations. "
                    "Cite provided sources in the Markdown text when appropriate."
                ),
            }

            recommendation_data = await self.ai_service.generate_structured_response(
                prompt=prompt,
                response_schema=response_schema,
                context=ai_context,
                model="gpt-4",
                user_id=user_id,
            )

            enhanced = self._enhance_recommendation(recommendation_data, gap)
            # Attach evidence context for downstream consumers
            if source_document_ids:
                enhanced["source_document_ids_used"] = source_document_ids
            if chat_citations:
                enhanced["citations"] = chat_citations
            if question:
                enhanced["original_question"] = question

            log_business_event(
                event_type="COMPLIANCE_RECOMMENDATION_GENERATED",
                entity_type="compliance_gap",
                entity_id=gap_id,
                action="recommend",
                user_id=user_id,
                details={
                    "compliance_domain": gap.compliance_domain,
                    "gap_type": gap.gap_type,
                    "risk_level": gap.risk_level,
                    "recommendation_type": recommendation_type,
                    "includes_implementation": include_implementation_plan,
                    "used_chat_context": bool(chat_item is not None),
                    "source_docs_count": len(source_document_ids),
                },
            )

            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="generate_compliance_recommendation_with_chat",
                duration_ms=duration_ms,
                success=True,
                item_count=1,
            )

            return enhanced

        except (ValidationException, ResourceNotFoundException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(
                f"Failed to generate compliance recommendation with chat for gap {gap_id}: {e}",
                exc_info=True,
            )
            raise BusinessLogicException(
                detail="Failed to generate compliance recommendation",
                error_code="COMPLIANCE_RECOMMENDATION_FAILED",
                context={"gap_id": gap_id},
            )

    def _build_recommendation_prompt(
        self,
        gap: ComplianceGap,
        recommendation_type: str,
        include_implementation_plan: bool,
        question: Optional[str] = None,
        prior_answer: Optional[str] = None,
        citations: Optional[List[Dict[str, Any]]] = None,
        source_document_ids: Optional[List[str]] = None,
    ) -> str:
        """Build a rich, structured prompt for a gap-specific recommendation.

        Goal: produce a comprehensive, board-ready recommendation document inside
        the `recommendation_text` field (Markdown with sections) and align all
        other structured fields to the same content.
        """

        # Core gap context rendered first so the model can ground details
        base_prompt = f"""
        You are a senior compliance consultant specializing in {gap.compliance_domain}.
        Create a comprehensive recommendation to address the following compliance gap.

        Gap Details
        - Title: {gap.gap_title}
        - Description: {gap.gap_description}
        - Type: {gap.gap_type}
        - Category: {gap.gap_category}
        - Risk Level: {gap.risk_level}
        - Business Impact: {gap.business_impact}
        - Regulatory Requirement: {gap.regulatory_requirement}
        - Original Question: {gap.original_question}

        Context
        - Compliance Domain: {gap.compliance_domain}
        - Detection Method: {gap.detection_method}
        - Confidence Score: {gap.confidence_score or 'N/A'}

        Current Status
        - Status: {gap.status}
        - Detected: {gap.detected_at.strftime('%Y-%m-%d')}
        - Age: {gap.get_age_in_days()} days
        """

        if gap.potential_fine_amount:
            base_prompt += f"\n- Potential Fine: ${gap.potential_fine_amount:,.2f}"

        if gap.assigned_to:
            base_prompt += f"\n- Assigned To: {gap.assigned_to}"

        if gap.due_date:
            base_prompt += f"\n- Due Date: {gap.due_date.strftime('%Y-%m-%d')}"

        # Explicit output contract to drive length, structure, and depth
        base_prompt += f"""

        Output Requirements
        - Audience: executive leadership and audit stakeholders.
        - Tone: formal, precise, action-oriented. Avoid vague statements.
        - Length: 700–1200 words in `recommendation_text`.
        - Format for `recommendation_text`: Markdown with H1/H2 headings and lists.
        - Be specific: reference the stated regulatory requirement and gap details.

        Populate the following fields in the structured response:
        0. recommendation_text: a full Markdown document with the sections below.
        1. root_cause_analysis: 1–2 concise paragraphs.
        2. remediation_actions: 6–10 specific, verifiable actions.
        3. risk_mitigation: 4–6 strategies tied to identified risks.
        4. best_practices: 5–8 items relevant to {gap.compliance_domain} and {gap.regulatory_requirement}.
        5. success_metrics: 5–8 measurable KPIs with targets and timeframes.
        6. priority_level: one of [critical, high, medium, low], aligned with {gap.risk_level}.
        7. estimated_effort: realistic duration and effort (e.g., "6–8 weeks, 2–3 FTE").
        {"8. implementation_phases, 9. resource_requirements, 10. potential_challenges, 11. mitigation_strategies (required)" if include_implementation_plan else ""}

        `recommendation_text` Section Layout (Markdown)
        # Recommendation: {gap.gap_title}
        ## Executive Summary
        - 3–5 sentences summarizing the compliance gap, business risk, and targeted outcome.
        ## Gap Analysis
        - Enumerate specific deficiencies observed (what is missing/insufficient today) mapped to {gap.regulatory_requirement}.
        ## Recommended Solution
        - Describe the target state and key policy, process, and control changes.
        ## Implementation Steps
        - Provide a numbered plan with phases; each phase includes:
          - Timeline (e.g., "Weeks 1–2"), Objectives, Activities, Deliverables
          - Control requirements satisfied and stakeholders responsible
        ## Resources Required
        - Personnel (roles with estimated hours), Technology/Tooling, Budget notes
        ## Success Criteria
        - Measurable outcomes and acceptance criteria tied to auditability
        ## Risk Mitigation
        - Likely risks, impact, likelihood, and mitigations
        ## Next Steps
        - Immediate actions for the next 1–2 weeks

        Important Guidance
        - Use the provided gap specifics; do not invent unrelated standards.
        - Where details are not provided, state reasonable assumptions explicitly.
        - Keep recommendations practical for a typical mid-size organization.

        Example format for `recommendation_text` (use as a style guide, not to copy verbatim):
        # Recommendation: Enhancing Organizational Policy for ISO 27001 Control A.7.1.3

        ## Executive Summary
        This recommendation aims to address compliance gaps ... ensure comprehensive compliance ...

        ## Gap Analysis
        The current policy lacks explicit documentation ... Statement of Applicability ...

        ## Recommended Solution
        Update policy to explicitly define and document requirements ... SoA ...

        ## Implementation Steps
        1. Update Policy Content (Timeline: 30 days) ...
        2. Review and Approval (Timeline: 15 days) ...
        3. Communication and Training (Timeline: 45 days) ...
        4. Implementation Rollout (Timeline: Ongoing) ...

        ## Resources Required
        Personnel ... Technology ... Budget ...

        ## Success Criteria
        ...

        ## Risk Mitigation
        ...

        ## Next Steps
        ...

        Now produce a {recommendation_type} recommendation that satisfies the above.
        Ensure the structured fields are consistent with the Markdown document.
        """

        guidance = (
            "\nAdditional Guidance\n"
            "- If regulatory requirement text is not provided, avoid inventing specific clauses; "
            "state assumptions and reference only provided sources.\n"
        )

        parts: List[str] = [base_prompt, guidance]

        # Inject chat context when present
        if question or prior_answer:
            parts.append("\nChat Context")
            if question:
                parts.append(f"- Original Question: {question}")
            if prior_answer:
                # Keep prior answer as context; the model should improve/expand on it
                parts.append("- Prior AI Analysis:\n" + prior_answer)

        # Inject document references as ground truth hints
        if citations:
            parts.append("\nDocument References (use these for citations):")
            for c in citations:
                idx = c.get("index")
                title = c.get("title") or "Unknown"
                filename = c.get("source_filename") or "Unknown"
                page = c.get("source_page_number")
                sim = c.get("similarity")
                parts.append(
                    f"[{idx}] {title} ({filename}{f', p. {page}' if page is not None else ''})"
                    + (f" — similarity {sim:.3f}" if isinstance(sim, (int, float)) else "")
                )

            parts.append(
                "\nCitation Instruction\n"
                "- In `recommendation_text`, cite the above sources inline using [n] where appropriate.\n"
                "- Do not cite sources not listed here.\n"
            )

        if source_document_ids:
            parts.append(
                "\nSource Document IDs (for grounding, not to output verbatim):\n"
                + ", ".join(source_document_ids)
            )

        # Encourage explicit assumptions to reduce hallucinations
        parts.append(
            "\nAssumptions & Unknowns\n"
            "- Where context is missing, list explicit assumptions and unknowns before proposing actions.\n"
        )

        return "\n".join(parts)

    def _build_recommendation_prompt_v2(
        self,
        gap: ComplianceGap,
        recommendation_type: str,
        include_implementation_plan: bool,
        question: Optional[str] = None,
        prior_answer: Optional[str] = None,
        citations: Optional[List[Dict[str, Any]]] = None,
        source_document_ids: Optional[List[str]] = None,
    ) -> str:
        """
        Compatibility wrapper for improved prompt builder. Delegates to
        `_build_recommendation_prompt` which now supports extended context.
        """
        return self._build_recommendation_prompt(
            gap=gap,
            recommendation_type=recommendation_type,
            include_implementation_plan=include_implementation_plan,
            question=question,
            prior_answer=prior_answer,
            citations=citations,
            source_document_ids=source_document_ids,
        )
    
    def _get_recommendation_schema(self, include_implementation_plan: bool) -> Dict[str, Any]:
        """Get schema for gap recommendation response."""
        
        properties = {
            "recommendation_text": {
                "type": "string",
                "description": "Comprehensive textual recommendation summarizing all aspects of addressing this gap"
            },
            "root_cause_analysis": {
                "type": "string",
                "description": "Analysis of why this gap exists"
            },
            "remediation_actions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific actions to address the gap"
            },
            "risk_mitigation": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Steps to reduce risk while implementing fix"
            },
            "best_practices": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Industry best practices relevant to this gap"
            },
            "success_metrics": {
                "type": "array",
                "items": {"type": "string"},
                "description": "How to measure success of remediation"
            },
            "priority_level": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low"],
                "description": "Implementation priority"
            },
            "estimated_effort": {
                "type": "string",
                "description": "Estimated time and effort required"
            }
        }
        
        required = ["recommendation_text", "root_cause_analysis", "remediation_actions", "priority_level"]
        
        if include_implementation_plan:
            properties.update({
                "implementation_phases": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "phase_name": {"type": "string"},
                            "timeline": {"type": "string"},
                            "activities": {"type": "array", "items": {"type": "string"}},
                            "resources": {"type": "array", "items": {"type": "string"}}
                        }
                    }
                },
                "resource_requirements": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "potential_challenges": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "mitigation_strategies": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            })
            required.extend(["implementation_phases", "resource_requirements"])
        
        return {
            "type": "object",
            "properties": properties,
            "required": required
        }

    def _enhance_recommendation(self, recommendation_data: Dict[str, Any], gap: ComplianceGap) -> Dict[str, Any]:
        """Enhance AI recommendation with gap context."""
        
        enhanced = recommendation_data.copy()
        enhanced.update({
            "gap_id": gap.id,
            "gap_title": gap.gap_title,
            "compliance_domain": gap.compliance_domain,
            "current_risk_level": gap.risk_level,
            "regulatory_requirement": gap.regulatory_requirement,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "gap_age_days": gap.get_age_in_days()
        })
        
        if gap.potential_fine_amount:
            enhanced["potential_fine_amount"] = float(gap.potential_fine_amount)
        
        return enhanced

# Factory function
def create_compliance_recommendation_service(
    ai_service: AIService,
    compliance_gap_repository: ComplianceGapRepository,
    user_repository: UserRepository,
    chat_history_repository: Optional[ChatHistoryRepository] = None,
) -> ComplianceRecommendationService:
    """Factory function to create ComplianceRecommendationService instance."""
    return ComplianceRecommendationService(
        ai_service,
        compliance_gap_repository,
        user_repository,
        chat_history_repository,
    )
