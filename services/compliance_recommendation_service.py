"""
ComplianceRecommendationService for generating AI-powered compliance recommendations.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timezone

from entities.compliance_gap import ComplianceGap, RiskLevel
from repositories.compliance_gap_repository import ComplianceGapRepository
from repositories.user_repository import UserRepository
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
        user_repository: UserRepository
    ):
        self.ai_service = ai_service
        self.gap_repository = compliance_gap_repository
        self.user_repository = user_repository

    """
    TODO: Require additional arguments, chat history, documents
    """
    async def generate_gap_recommendation(
        self, 
        gap_id: str, 
        user_id: str,
        recommendation_type: str = "comprehensive",
        include_implementation_plan: bool = True
    ) -> Dict[str, Any]:
        """Generate AI-powered recommendation for a specific compliance gap."""
        try:
            import time
            start_time = time.time()
            
            # Validate user and get gap with access control
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive user",
                    field="user_id",
                    value=user_id
                )
            
            # Get the compliance gap
            gap = await self.gap_repository.get_by_id(gap_id)
            if not gap:
                raise ResourceNotFoundException(
                    resource_type="ComplianceGap",
                    resource_id=gap_id
                )
            
            # Check user access to compliance domain
            if not (user.is_admin() or user.can_access_domain(gap.compliance_domain)):
                raise AuthorizationException(
                    detail=f"Access denied to compliance domain: {gap.compliance_domain}",
                    error_code="DOMAIN_ACCESS_DENIED"
                )
            
            # Build recommendation prompt
            prompt = self._build_recommendation_prompt(gap, recommendation_type, include_implementation_plan)
            
            # Define response schema
            response_schema = self._get_recommendation_schema(include_implementation_plan)
            
            # Generate AI recommendation
            ai_context = {
                "role": "compliance expert and consultant",
                "domain": gap.compliance_domain,
                "instructions": f"Provide practical, actionable recommendations for {gap.compliance_domain} compliance."
            }
            
            recommendation_data = await self.ai_service.generate_structured_response(
                prompt=prompt,
                response_schema=response_schema,
                context=ai_context,
                model="gpt-4",  # Use GPT-4 for better compliance reasoning
                user_id=user_id
            )
            
            # Enhance recommendation with gap context
            enhanced_recommendation = self._enhance_recommendation(recommendation_data, gap)
            
            # Log business event
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
                    "includes_implementation": include_implementation_plan
                }
            )
            
            # Log performance
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="generate_compliance_recommendation",
                duration_ms=duration_ms,
                success=True,
                item_count=1
            )
            
            return enhanced_recommendation
            
        except (ValidationException, ResourceNotFoundException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to generate compliance recommendation for gap {gap_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to generate compliance recommendation",
                error_code="COMPLIANCE_RECOMMENDATION_FAILED",
                context={"gap_id": gap_id}
            )

    def _build_recommendation_prompt(
        self, 
        gap: ComplianceGap, 
        recommendation_type: str,
        include_implementation_plan: bool
    ) -> str:
        """Build a rich, structured prompt for a gap-specific recommendation.

        Goal: produce a comprehensive, board-ready recommendation document inside
        the `recommendation_text` field (Markdown with sections) and align all
        other structured fields to the same content.
        """

        # Core gap context rendered first so the model can ground details
        prompt = f"""
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
            prompt += f"\n- Potential Fine: ${gap.potential_fine_amount:,.2f}"

        if gap.assigned_to:
            prompt += f"\n- Assigned To: {gap.assigned_to}"

        if gap.due_date:
            prompt += f"\n- Due Date: {gap.due_date.strftime('%Y-%m-%d')}"

        # Explicit output contract to drive length, structure, and depth
        prompt += f"""

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

        return prompt

    def _build_remediation_plan_prompt(
        self, 
        gaps: List[ComplianceGap], 
        timeline_weeks: int,
        resource_constraints: Optional[Dict[str, Any]] = None
    ) -> str:
        """Build prompt for remediation plan."""
        
        prompt = f"""
        Create a comprehensive remediation plan to address the following compliance gaps within {timeline_weeks} weeks:

        **Gaps to Address:**
        """
        
        for i, gap in enumerate(gaps, 1):
            prompt += f"""
        {i}. {gap.gap_title}
           - Risk: {gap.risk_level}
           - Domain: {gap.compliance_domain}
           - Category: {gap.gap_category}
           - Regulatory: {gap.regulatory_requirement}
           - Age: {gap.get_age_in_days()} days
        """
        
        if resource_constraints:
            prompt += f"\n**Resource Constraints:**\n{resource_constraints}"
        
        prompt += f"""
        
        **Timeline:** {timeline_weeks} weeks

        **Request:**
        Create a detailed remediation plan that includes:
        1. Phase breakdown (with timeline)
        2. Task prioritization and sequencing
        3. Resource requirements per phase
        4. Dependencies and critical path
        5. Milestones and deliverables
        6. Risk mitigation during implementation
        7. Success criteria and validation
        8. Communication and stakeholder management
        9. Contingency planning
        
        Prioritize regulatory requirements and high-risk items while considering practical implementation constraints.
        """
        
        return prompt

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

    def _get_remediation_plan_schema(self) -> Dict[str, Any]:
        """Get schema for remediation plan response."""
        
        return {
            "type": "object",
            "properties": {
                "executive_summary": {
                    "type": "string",
                    "description": "High-level summary of the remediation plan"
                },
                "phases": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "phase_name": {"type": "string"},
                            "duration_weeks": {"type": "number"},
                            "objectives": {"type": "array", "items": {"type": "string"}},
                            "tasks": {"type": "array", "items": {"type": "string"}},
                            "deliverables": {"type": "array", "items": {"type": "string"}},
                            "resources_needed": {"type": "array", "items": {"type": "string"}}
                        }
                    }
                },
                "critical_path": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Critical path items that could delay the project"
                },
                "milestones": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "milestone": {"type": "string"},
                            "target_week": {"type": "number"},
                            "success_criteria": {"type": "string"}
                        }
                    }
                },
                "risk_mitigation": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "total_estimated_effort": {
                    "type": "string",
                    "description": "Total estimated effort in person-weeks"
                },
                "success_criteria": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
            "required": ["executive_summary", "phases", "milestones", "total_estimated_effort"]
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
    user_repository: UserRepository
) -> ComplianceRecommendationService:
    """Factory function to create ComplianceRecommendationService instance."""
    return ComplianceRecommendationService(ai_service, compliance_gap_repository, user_repository)
