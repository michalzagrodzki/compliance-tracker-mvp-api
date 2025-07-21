import logging
from typing import Dict, List, Any, Union
from fastapi import HTTPException
from openai import OpenAI
from config.config import settings
from services.schemas import ComplianceGap

logger = logging.getLogger(__name__)

def get_audience_context(target_audience: str) -> Dict[str, str]:
    """Get audience-specific context for content generation."""
    audience_contexts = {
        "executives": {
            "tone": "strategic and decisive",
            "focus": "business impact, ROI, competitive advantage, strategic decision-making",
            "format": "executive briefing with clear recommendations and action items",
            "length": "concise, 3-4 paragraphs maximum per section",
            "language": "business language, avoid technical jargon, focus on outcomes",
            "key_concerns": "bottom-line impact, competitive positioning, regulatory risk, investment priorities"
        },
        "compliance_team": {
            "tone": "detailed and procedural", 
            "focus": "regulatory requirements, control implementation, audit readiness, compliance procedures",
            "format": "comprehensive analysis with action items and implementation guidance",
            "length": "detailed, 5-7 paragraphs with specific procedural guidance",
            "language": "compliance terminology, regulatory references, control frameworks",
            "key_concerns": "regulatory adherence, control gaps, implementation timelines, audit preparation"
        },
        "auditors": {
            "tone": "objective and evidence-based",
            "focus": "control effectiveness, evidence gaps, audit findings, risk assessment methodology",
            "format": "systematic assessment with citations and audit trail references",
            "length": "comprehensive, 6-8 paragraphs with detailed findings", 
            "language": "audit terminology, risk-based language, evidence references",
            "key_concerns": "control testing, evidence sufficiency, materiality, audit scope coverage"
        },
        "regulators": {
            "tone": "formal and compliant",
            "focus": "regulatory adherence, statutory requirements, corrective actions, legal compliance",
            "format": "formal regulatory response with detailed compliance status",
            "length": "detailed, 7-10 paragraphs with comprehensive regulatory coverage",
            "language": "regulatory terminology, legal compliance focus, statutory references",
            "key_concerns": "regulatory violations, corrective action plans, compliance timelines, legal exposure"
        },
        "board": {
            "tone": "strategic and governance-focused",
            "focus": "governance oversight, strategic risk, fiduciary responsibility, organizational reputation",
            "format": "board presentation with governance implications and strategic recommendations",
            "length": "strategic overview, 4-5 paragraphs with governance focus",
            "language": "governance terminology, strategic business language, fiduciary focus",
            "key_concerns": "organizational risk, governance effectiveness, strategic alignment, stakeholder impact"
        }
    }
    return audience_contexts.get(target_audience, audience_contexts["compliance_team"])

def generate_target_audience_summary(
    audit_report: Dict[str, Any],
    compliance_gaps: List[ComplianceGap],
) -> str:

    target_audience = audit_report.get('target_audience', 'compliance_team')
    audience_context = get_audience_context(target_audience)
    
    # Build context from audit report
    audit_context = _build_audit_context(audit_report)
    
    # Build audience-specific compliance gaps analysis
    gaps_analysis = _build_audience_specific_gaps_analysis(compliance_gaps, audience_context)
    
    # Build audience-specific recommendations
    recommendations_analysis = _build_audience_specific_recommendations(compliance_gaps, audience_context)
    
    # Build audience-specific action items
    action_items = _build_audience_specific_action_items(audit_report, compliance_gaps, audience_context)
    
    # Create the audience-specific prompt
    system_message, user_prompt = _create_target_audience_prompt(
        audit_context,
        gaps_analysis,
        recommendations_analysis,
        action_items,
        target_audience,
        audience_context
    )
    
    client = OpenAI(api_key=settings.openai_api_key)
    
    try:
        completion = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {
                    "role": "system",
                    "content": system_message
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ],
            temperature=0.1,
            max_tokens=2500,
        )
    except Exception as e:
        logger.error("OpenAI ChatCompletion failed for target audience summary", exc_info=True)
        raise HTTPException(status_code=502, detail=f"OpenAI API error: {e}")
    
    summary = completion.choices[0].message.content.strip()
    
    logger.info(f"Successfully generated target audience summary for '{target_audience}' on audit report "
               f"'{audit_report.get('report_title', 'Unknown')}' with {len(compliance_gaps)} gaps")
    
    return summary

def _get_gap_value(gap: Union[Dict[str, Any], ComplianceGap], key: str, default: Any = None) -> Any:
    """Helper function to get value from gap object regardless of type."""
    if isinstance(gap, dict):
        return gap.get(key, default)
    else:
        return getattr(gap, key, default)

def _build_audit_context(audit_report: Dict[str, Any]) -> str:
    """Build audit context section from audit report data."""
    
    context_parts = []
    
    # Basic audit information
    context_parts.append(f"**Audit Title:** {audit_report.get('report_title', 'N/A')}")
    context_parts.append(f"**Compliance Domain:** {audit_report.get('compliance_domain', 'N/A')}")
    context_parts.append(f"**Report Type:** {audit_report.get('report_type', 'N/A')}")
    context_parts.append(f"**Target Audience:** {audit_report.get('target_audience', 'N/A')}")
    context_parts.append(f"**Confidentiality Level:** {audit_report.get('confidentiality_level', 'N/A')}")
    
    # Audit scope metrics
    context_parts.append(f"**Documents Reviewed:** {len(audit_report.get('document_ids', []))}")
    context_parts.append(f"**Chat Sessions:** {len(audit_report.get('chat_history_ids', []))}")
    context_parts.append(f"**PDF Sources:** {len(audit_report.get('pdf_ingestion_ids', []))}")
    
    # Configuration details
    if audit_report.get('include_technical_details', False):
        context_parts.append("**Technical Details:** Included")
    if audit_report.get('include_source_citations', False):
        context_parts.append("**Source Citations:** Included")
    if audit_report.get('external_auditor_access', False):
        context_parts.append("**External Auditor Access:** Granted")
    
    return "\n".join(context_parts)

def _build_audience_specific_gaps_analysis(
    compliance_gaps: List[Union[Dict[str, Any], ComplianceGap]], 
    audience_context: Dict[str, str]
) -> str:
    """Build compliance gaps analysis tailored to specific audience."""
    
    if not compliance_gaps:
        return "**No compliance gaps identified in this audit.**"
    
    analysis_parts = []
    target_focus = audience_context.get('focus', '')
    
    # Risk level distribution
    risk_groups = {}
    for gap in compliance_gaps:
        risk_level = _get_gap_value(gap, 'risk_level', 'medium')
        if risk_level not in risk_groups:
            risk_groups[risk_level] = []
        risk_groups[risk_level].append(gap)
    
    # Audience-specific gap presentation
    if 'business impact' in target_focus or 'strategic' in target_focus:
        # Executive/Board focus - emphasize business impact
        analysis_parts.append("**Business Impact Assessment:**")
        
        high_impact_gaps = [g for g in compliance_gaps if _get_gap_value(g, 'business_impact', 'medium') == 'high']
        medium_impact_gaps = [g for g in compliance_gaps if _get_gap_value(g, 'business_impact', 'medium') == 'medium']
        
        if high_impact_gaps:
            analysis_parts.append(f"- **High Business Impact:** {len(high_impact_gaps)} gaps affecting critical operations")
        if medium_impact_gaps:
            analysis_parts.append(f"- **Medium Business Impact:** {len(medium_impact_gaps)} gaps affecting important processes")
        
        # Financial exposure
        total_potential_fines = sum(
            float(_get_gap_value(gap, 'potential_fine_amount', 0))
            for gap in compliance_gaps
            if _get_gap_value(gap, 'potential_fine_amount', 0)
        )
        if total_potential_fines > 0:
            analysis_parts.append(f"- **Potential Financial Exposure:** ${total_potential_fines:,.2f}")
    
    elif 'regulatory' in target_focus or 'compliance' in target_focus:
        # Compliance team/Regulator focus - emphasize regulatory requirements
        analysis_parts.append("**Regulatory Compliance Status:**")
        
        regulatory_gaps = [g for g in compliance_gaps if _get_gap_value(g, 'regulatory_requirement', False)]
        non_regulatory_gaps = [g for g in compliance_gaps if not _get_gap_value(g, 'regulatory_requirement', False)]
        
        analysis_parts.append(f"- **Mandatory Regulatory Gaps:** {len(regulatory_gaps)} gaps requiring immediate compliance action")
        analysis_parts.append(f"- **Best Practice Gaps:** {len(non_regulatory_gaps)} gaps for continuous improvement")
        
        # Category breakdown for compliance teams
        category_groups = {}
        for gap in compliance_gaps:
            category = _get_gap_value(gap, 'gap_category', 'uncategorized')
            category_groups[category] = category_groups.get(category, 0) + 1
        
        if category_groups:
            analysis_parts.append("\n**Compliance Area Breakdown:**")
            for category, count in category_groups.items():
                analysis_parts.append(f"- {category.replace('_', ' ').title()}: {count} gaps")
    
    elif 'audit' in target_focus or 'control effectiveness' in target_focus:
        # Auditor focus - emphasize control effectiveness and evidence
        analysis_parts.append("**Control Effectiveness Assessment:**")
        
        # Detection method analysis
        detection_methods = {}
        for gap in compliance_gaps:
            method = _get_gap_value(gap, 'detection_method', 'unknown')
            detection_methods[method] = detection_methods.get(method, 0) + 1
        
        analysis_parts.append("**Gap Detection Methods:**")
        for method, count in detection_methods.items():
            analysis_parts.append(f"- {method.replace('_', ' ').title()}: {count} gaps")
        
        # Confidence scores
        confidence_scores = [
            float(_get_gap_value(gap, 'confidence_score', 0))
            for gap in compliance_gaps
            if _get_gap_value(gap, 'confidence_score', 0)
        ]
        if confidence_scores:
            avg_confidence = sum(confidence_scores) / len(confidence_scores)
            analysis_parts.append(f"\n**Average Gap Confidence Score:** {avg_confidence:.2f}")
    
    # Common risk level summary for all audiences
    analysis_parts.append(f"\n**Risk Level Distribution:**")
    for risk_level in ['high', 'medium', 'low']:
        count = len(risk_groups.get(risk_level, []))
        if count > 0:
            analysis_parts.append(f"- {risk_level.title()}: {count} gaps")
    
    return "\n".join(analysis_parts)

def _build_audience_specific_recommendations(
    compliance_gaps: List[Union[Dict[str, Any], ComplianceGap]], 
    audience_context: Dict[str, str]
) -> str:
    """Build recommendations analysis tailored to specific audience."""
    
    if not compliance_gaps:
        return "**No specific recommendations required.**"
    
    recommendations_parts = []
    target_focus = audience_context.get('focus', '')
    language_style = audience_context.get('language', '')
    
    # Get gaps with recommendations
    gaps_with_recommendations = [
        gap for gap in compliance_gaps 
        if _get_gap_value(gap, 'recommendation_text', None) and _get_gap_value(gap, 'recommendation_text', '').strip()
    ]
    
    if not gaps_with_recommendations:
        return "**No specific recommendations available from gap analysis.**"
    
    if 'business' in target_focus or 'strategic' in target_focus:
        # Executive/Board focus - strategic recommendations
        recommendations_parts.append("**Strategic Recommendations:**")
        
        # High impact recommendations first
        high_impact_recs = [
            gap for gap in gaps_with_recommendations
            if _get_gap_value(gap, 'business_impact', 'medium') == 'high'
        ]
        
        if high_impact_recs:
            recommendations_parts.append("\n**Priority Business Actions:**")
            for i, gap in enumerate(high_impact_recs[:3], 1):
                gap_title = _get_gap_value(gap, 'gap_title', f'Gap #{i}')
                recommendation = _get_gap_value(gap, 'recommendation_text', '')
                
                # Simplify technical language for executives
                business_rec = _translate_to_business_language(recommendation)
                recommendations_parts.append(f"{i}. **{gap_title}**")
                recommendations_parts.append(f"   - *Business Action:* {business_rec}")
        
        # ROI and investment focus
        recommendations_parts.append("\n**Investment Priorities:**")
        recommendations_parts.append("- Focus resources on high-impact gaps for maximum ROI")
        recommendations_parts.append("- Consider outsourcing complex technical implementations")
        recommendations_parts.append("- Establish clear timelines and success metrics")
    
    elif 'regulatory' in target_focus or 'compliance' in target_focus:
        # Compliance team focus - detailed procedural recommendations
        recommendations_parts.append("**Compliance Implementation Guidance:**")
        
        # Regulatory requirements first
        regulatory_recs = [
            gap for gap in gaps_with_recommendations
            if _get_gap_value(gap, 'regulatory_requirement', False)
        ]
        
        if regulatory_recs:
            recommendations_parts.append("\n**Mandatory Regulatory Actions:**")
            for i, gap in enumerate(regulatory_recs[:5], 1):
                gap_title = _get_gap_value(gap, 'gap_title', f'Gap #{i}')
                recommendation = _get_gap_value(gap, 'recommendation_text', '')
                actions = _get_gap_value(gap, 'recommended_actions', [])
                
                recommendations_parts.append(f"{i}. **{gap_title}**")
                recommendations_parts.append(f"   - *Implementation:* {recommendation}")
                
                if actions and isinstance(actions, list):
                    recommendations_parts.append("   - *Action Steps:*")
                    for action in actions[:3]:
                        recommendations_parts.append(f"     - {action}")
        
        # Best practices
        best_practice_recs = [
            gap for gap in gaps_with_recommendations
            if not _get_gap_value(gap, 'regulatory_requirement', False)
        ]
        
        if best_practice_recs:
            recommendations_parts.append(f"\n**Best Practice Improvements ({len(best_practice_recs)} items):**")
            recommendations_parts.append("- Schedule for implementation after mandatory requirements")
            recommendations_parts.append("- Consider as part of continuous improvement program")
    
    elif 'audit' in target_focus:
        # Auditor focus - evidence and control recommendations
        recommendations_parts.append("**Audit and Control Recommendations:**")
        
        # High confidence recommendations
        high_confidence_recs = [
            gap for gap in gaps_with_recommendations
            if _get_gap_value(gap, 'confidence_score', 0) > 0.8
        ]
        
        if high_confidence_recs:
            recommendations_parts.append(f"\n**High Confidence Findings ({len(high_confidence_recs)} gaps):**")
            for i, gap in enumerate(high_confidence_recs[:4], 1):
                gap_title = _get_gap_value(gap, 'gap_title', f'Gap #{i}')
                recommendation = _get_gap_value(gap, 'recommendation_text', '')
                confidence = _get_gap_value(gap, 'confidence_score', 0)
                
                recommendations_parts.append(f"{i}. **{gap_title}** (Confidence: {float(confidence):.2f})")
                recommendations_parts.append(f"   - *Control Recommendation:* {recommendation}")
        
        # Evidence collection recommendations
        recommendations_parts.append("\n**Audit Evidence Recommendations:**")
        recommendations_parts.append("- Document all remediation actions with appropriate evidence")
        recommendations_parts.append("- Establish testing procedures for implemented controls")
        recommendations_parts.append("- Schedule follow-up audits to verify effectiveness")
    
    return "\n".join(recommendations_parts)

def _build_audience_specific_action_items(
    audit_report: Dict[str, Any], 
    compliance_gaps: List[Union[Dict[str, Any], ComplianceGap]], 
    audience_context: Dict[str, str]
) -> str:
    """Build action items tailored to specific audience."""
    
    action_parts = []
    target_audience = audit_report.get('target_audience', 'compliance_team')
    total_gaps = len(compliance_gaps)
    
    if target_audience in ['executives', 'board']:
        action_parts.append("**Executive Action Items:**")
        action_parts.append("1. **Resource Allocation** - Approve budget for gap remediation program")
        action_parts.append("2. **Governance Oversight** - Establish executive steering committee")
        action_parts.append("3. **Timeline Approval** - Review and approve implementation timeline")
        action_parts.append("4. **External Support** - Consider engaging external consultants for complex gaps")
        action_parts.append("5. **Progress Monitoring** - Establish monthly progress reviews")
        
    elif target_audience == 'compliance_team':
        action_parts.append("**Compliance Team Action Items:**")
        action_parts.append("1. **Gap Prioritization** - Develop detailed implementation roadmap")
        action_parts.append("2. **Resource Planning** - Identify internal and external resource needs")
        action_parts.append("3. **Policy Updates** - Review and update affected policies and procedures")
        action_parts.append("4. **Training Programs** - Develop staff training on new controls")
        action_parts.append("5. **Documentation** - Maintain detailed records of all remediation activities")
        action_parts.append("6. **Vendor Management** - Coordinate with external vendors as needed")
        
    elif target_audience == 'auditors':
        action_parts.append("**Audit Action Items:**")
        action_parts.append("1. **Follow-up Testing** - Schedule re-testing of implemented controls")
        action_parts.append("2. **Evidence Collection** - Document all remediation evidence")
        action_parts.append("3. **Control Validation** - Verify effectiveness of new controls")
        action_parts.append("4. **Risk Assessment** - Update risk assessments based on findings")
        action_parts.append("5. **Audit Report** - Prepare detailed audit findings report")
        
    elif target_audience == 'regulators':
        action_parts.append("**Regulatory Response Action Items:**")
        action_parts.append("1. **Corrective Action Plan** - Submit detailed remediation plan")
        action_parts.append("2. **Timeline Compliance** - Ensure all actions meet regulatory deadlines")
        action_parts.append("3. **Progress Reporting** - Provide regular status updates")
        action_parts.append("4. **Evidence Submission** - Prepare evidence packages for regulatory review")
        action_parts.append("5. **Legal Review** - Ensure all actions meet legal requirements")
    
    # Timeline considerations
    high_risk_gaps = len([g for g in compliance_gaps if _get_gap_value(g, 'risk_level', 'medium') == 'high'])
    
    action_parts.append(f"\n**Timeline Considerations:**")
    if high_risk_gaps > 0:
        action_parts.append(f"- **Immediate (30 days):** Address {high_risk_gaps} high-risk gaps")
        action_parts.append(f"- **Short-term (90 days):** Complete remaining critical items")
        action_parts.append(f"- **Medium-term (6 months):** Full compliance program implementation")
    else:
        action_parts.append("- **Short-term (60 days):** Address identified gaps")
        action_parts.append("- **Medium-term (6 months):** Continuous improvement program")
    
    return "\n".join(action_parts)

def _translate_to_business_language(technical_recommendation: str) -> str:
    """Convert technical recommendations to business-friendly language."""
    
    # Simple translation mapping for common technical terms
    translations = {
        'implement encryption': 'secure data protection',
        'access controls': 'user permission management',
        'vulnerability assessment': 'security review',
        'incident response': 'emergency procedures',
        'backup procedures': 'data recovery processes',
        'network segmentation': 'system isolation',
        'authentication': 'user verification',
        'monitoring': 'oversight system',
        'patch management': 'system updates',
        'firewall': 'security barrier'
    }
    
    business_rec = technical_recommendation.lower()
    for technical_term, business_term in translations.items():
        business_rec = business_rec.replace(technical_term, business_term)
    
    # Capitalize first letter
    return business_rec.capitalize()

def _create_target_audience_prompt(
    audit_context: str,
    gaps_analysis: str,
    recommendations_analysis: str,
    action_items: str,
    target_audience: str,
    audience_context: Dict[str, str]
) -> tuple[str, str]:
    """Create the OpenAI prompt for target audience-specific summary."""
    
    # System message tailored to the target audience
    system_message = (
        f"You are an expert compliance analyst specializing in {target_audience}-focused reporting. "
        f"Generate professional compliance summaries specifically tailored for {target_audience}. "
        f"Your tone should be {audience_context['tone']} and your focus should be on "
        f"{audience_context['focus']}. Use {audience_context['language']} and format the response as "
        f"{audience_context['format']}. Keep sections {audience_context['length']} and address "
        f"the key concerns of this audience: {audience_context['key_concerns']}."
    )
    
    user_prompt = f"""
Please generate a comprehensive compliance summary specifically tailored for {target_audience}.

## Audit Context
{audit_context}

## Compliance Gaps Analysis
{gaps_analysis}

## Recommendations Analysis
{recommendations_analysis}

## Action Items
{action_items}

## Summary Requirements
- **Target Audience:** {target_audience}
- **Tone:** {audience_context['tone']}
- **Focus Areas:** {audience_context['focus']}
- **Format:** {audience_context['format']}
- **Length Guidelines:** {audience_context['length']}
- **Language Style:** {audience_context['language']}
- **Key Concerns to Address:** {audience_context['key_concerns']}

## Output Structure
Generate a {target_audience}-specific summary with the following sections:
1. **Summary Overview** - Tailored opening that addresses primary audience concerns
2. **Key Findings** - Most relevant findings for this audience
3. **Impact Assessment** - How gaps affect areas of concern for this audience  
4. **Priority Recommendations** - Actions prioritized for this audience's decision-making needs
5. **Next Steps** - Clear, actionable next steps appropriate for this audience's role

Format the response in professional markdown suitable for {target_audience} review and decision-making.
"""
    
    return system_message, user_prompt