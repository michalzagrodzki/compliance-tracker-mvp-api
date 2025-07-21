import logging
from typing import Dict, List, Any, Union
from fastapi import HTTPException
from openai import OpenAI
from pydantic import BaseModel, Field
from uuid import UUID
from config.config import settings
from services.schemas import ComplianceGap

logger = logging.getLogger(__name__)

# Response model for control risk prioritization
class ControlRiskPrioritizationResponse(BaseModel):
    """Response model for control risk prioritization analysis"""
    risk_prioritization_analysis: str = Field(description="Generated control risk prioritization analysis in markdown format")
    audit_session_id: UUID
    compliance_domain: str
    total_gaps: int
    high_risk_gaps: int
    medium_risk_gaps: int
    low_risk_gaps: int
    regulatory_gaps: int
    affected_control_families: int = Field(description="Number of ISO27001 control families affected by gaps")
    certification_readiness_score: str = Field(description="ISO27001 certification readiness assessment (High/Medium-High/Medium/Low)")
    estimated_investment_range: str = Field(description="Estimated investment range for gap remediation")
    priority_1_gaps: int = Field(description="Number of Priority 1 (immediate action) gaps")
    priority_2_gaps: int = Field(description="Number of Priority 2 (strategic implementation) gaps")
    priority_3_gaps: int = Field(description="Number of Priority 3 (planned improvements) gaps")
    estimated_timeline_months: str = Field(description="Estimated timeline for ISO27001 certification readiness")
    total_potential_fines: float = Field(description="Total potential financial exposure from compliance gaps")
    generation_metadata: Dict[str, Any] = Field(
        description="Metadata about the control risk prioritization generation process"
    )

def generate_control_risk_prioritization(
    audit_report: Dict[str, Any],
    compliance_gaps: List[ComplianceGap],
) -> str:
    """
    Generate a control risk prioritization analysis using OpenAI API based on audit report and compliance gaps.
    
    Args:
        audit_report: Full audit report object with all metadata
        compliance_gaps: List of compliance gap objects
    
    Returns:
        Formatted markdown control risk prioritization analysis
    """
    
    # Build context from audit report
    audit_context = _build_audit_context(audit_report)
    
    # Build control gaps analysis
    control_gaps_analysis = _build_control_gaps_analysis(compliance_gaps)
    
    # Build control family analysis
    control_family_analysis = _build_control_family_analysis(compliance_gaps)
    
    # Build business impact assessment
    business_impact_analysis = _build_business_impact_analysis(compliance_gaps)
    
    # Build investment priority analysis
    investment_priorities = _build_investment_priorities_analysis(compliance_gaps)
    
    # Create the control risk prioritization prompt
    system_message, user_prompt = _create_control_risk_prioritization_prompt(
        audit_context,
        control_gaps_analysis,
        control_family_analysis,
        business_impact_analysis,
        investment_priorities
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
        logger.error("OpenAI ChatCompletion failed for control risk prioritization", exc_info=True)
        raise HTTPException(status_code=502, detail=f"OpenAI API error: {e}")
    
    analysis = completion.choices[0].message.content.strip()
    
    logger.info(f"Successfully generated control risk prioritization for audit report "
               f"'{audit_report.get('report_title', 'Unknown')}' with {len(compliance_gaps)} gaps")
    
    return analysis

def calculate_risk_prioritization_metrics(
    audit_report: Dict[str, Any],
    compliance_gaps: List[ComplianceGap],
) -> Dict[str, Any]:
    """
    Calculate all metrics needed for the ControlRiskPrioritizationResponse.
    
    Args:
        audit_report: Full audit report object with all metadata
        compliance_gaps: List of compliance gap objects
    
    Returns:
        Dictionary containing all calculated metrics
    """
    
    # Basic gap statistics
    total_gaps = len(compliance_gaps)
    high_risk_gaps = len([gap for gap in compliance_gaps if gap.risk_level == 'high'])
    medium_risk_gaps = len([gap for gap in compliance_gaps if gap.risk_level == 'medium'])
    low_risk_gaps = len([gap for gap in compliance_gaps if gap.risk_level == 'low'])
    regulatory_gaps = len([gap for gap in compliance_gaps if gap.regulatory_requirement])
    
    # Calculate control family coverage
    control_families_affected = set()
    for gap in compliance_gaps:
        category = gap.gap_category.lower() if gap.gap_category else 'other'
        if 'access' in category or 'authentication' in category:
            control_families_affected.add('A.9 - Access Control')
        elif 'encryption' in category or 'crypto' in category:
            control_families_affected.add('A.10 - Cryptography')
        elif 'network' in category or 'communication' in category:
            control_families_affected.add('A.13 - Communications Security')
        elif 'incident' in category:
            control_families_affected.add('A.16 - Information Security Incident Management')
        elif 'backup' in category or 'continuity' in category:
            control_families_affected.add('A.17 - Business Continuity Management')
        elif 'compliance' in category:
            control_families_affected.add('A.18 - Compliance')
        elif 'asset' in category:
            control_families_affected.add('A.8 - Asset Management')
        elif 'physical' in category:
            control_families_affected.add('A.11 - Physical and Environmental Security')
        elif 'operations' in category:
            control_families_affected.add('A.12 - Operations Security')
        elif 'policy' in category or 'governance' in category:
            control_families_affected.add('A.5 - Information Security Policies')
        elif 'hr' in category or 'human' in category:
            control_families_affected.add('A.7 - Human Resource Security')
        else:
            control_families_affected.add('A.6 - Organization of Information Security')
    
    # Determine certification readiness and timeline
    if high_risk_gaps == 0:
        certification_readiness = "High"
        timeline = "3-6 months"
    elif high_risk_gaps <= 2:
        certification_readiness = "Medium-High"
        timeline = "6-9 months"
    elif high_risk_gaps <= 5:
        certification_readiness = "Medium"
        timeline = "9-12 months"
    else:
        certification_readiness = "Low"
        timeline = "12-18 months"
    
    # Determine investment range
    if total_gaps <= 5:
        investment_range = "$50K-$150K"
    elif total_gaps <= 10:
        investment_range = "$150K-$300K"
    else:
        investment_range = "$300K-$500K"
    
    # Calculate priority distribution
    priority_1_gaps = len([
        gap for gap in compliance_gaps 
        if gap.risk_level == 'high' and gap.business_impact == 'high'
    ])
    
    high_risk_medium_impact = len([
        gap for gap in compliance_gaps 
        if gap.risk_level == 'high' and gap.business_impact == 'medium'
    ])
    
    medium_risk_high_impact = len([
        gap for gap in compliance_gaps 
        if gap.risk_level == 'medium' and gap.business_impact == 'high'
    ])
    
    priority_2_gaps = high_risk_medium_impact + medium_risk_high_impact
    priority_3_gaps = total_gaps - priority_1_gaps - priority_2_gaps
    
    # Calculate total potential fines
    total_potential_fines = 0.0
    for gap in compliance_gaps:
        if gap.potential_fine_amount:
            fine_amount = float(gap.potential_fine_amount)
            total_potential_fines += fine_amount
    
    return {
        "total_gaps": total_gaps,
        "high_risk_gaps": high_risk_gaps,
        "medium_risk_gaps": medium_risk_gaps,
        "low_risk_gaps": low_risk_gaps,
        "regulatory_gaps": regulatory_gaps,
        "affected_control_families": len(control_families_affected),
        "certification_readiness_score": certification_readiness,
        "estimated_investment_range": investment_range,
        "priority_1_gaps": priority_1_gaps,
        "priority_2_gaps": priority_2_gaps,
        "priority_3_gaps": priority_3_gaps,
        "estimated_timeline_months": timeline,
        "total_potential_fines": total_potential_fines,
    }

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
    context_parts.append(f"**Industry Sector:** IT Services")  # Hardcoded as requested
    context_parts.append(f"**Company Size:** Medium Enterprise")  # Hardcoded as requested
    context_parts.append(f"**Geographic Footprint:** Multi-regional operations")  # Hardcoded as requested
    context_parts.append(f"**Target Audience:** {audit_report.get('target_audience', 'N/A')}")
    context_parts.append(f"**Confidentiality Level:** {audit_report.get('confidentiality_level', 'N/A')}")
    
    # Audit scope metrics
    context_parts.append(f"**Documents Reviewed:** {len(audit_report.get('document_ids', []))}")
    context_parts.append(f"**Chat Sessions:** {len(audit_report.get('chat_history_ids', []))}")
    context_parts.append(f"**PDF Sources:** {len(audit_report.get('pdf_ingestion_ids', []))}")
    
    return "\n".join(context_parts)

def _build_control_gaps_analysis(compliance_gaps: List[Union[Dict[str, Any], ComplianceGap]]) -> str:
    """Build control gaps analysis focusing on control families and risk levels."""
    
    if not compliance_gaps:
        return "**No control gaps identified in this audit.**"
    
    analysis_parts = []
    
    # Group gaps by risk level
    risk_groups = {
        'high': [g for g in compliance_gaps if _get_gap_value(g, 'risk_level', 'medium') == 'high'],
        'medium': [g for g in compliance_gaps if _get_gap_value(g, 'risk_level', 'medium') == 'medium'],
        'low': [g for g in compliance_gaps if _get_gap_value(g, 'risk_level', 'medium') == 'low']
    }
    
    # Control gap summary
    total_gaps = len(compliance_gaps)
    analysis_parts.append(f"**Total Control Gaps Identified:** {total_gaps}")
    
    analysis_parts.append("**Risk Distribution:**")
    for risk_level, gaps in risk_groups.items():
        if gaps:
            percentage = (len(gaps) / total_gaps) * 100
            analysis_parts.append(f"- **{risk_level.title()} Risk:** {len(gaps)} gaps ({percentage:.1f}%)")
    
    # Regulatory compliance gaps
    regulatory_gaps = [g for g in compliance_gaps if _get_gap_value(g, 'regulatory_requirement', False)]
    if regulatory_gaps:
        reg_percentage = (len(regulatory_gaps) / total_gaps) * 100
        analysis_parts.append(f"- **Regulatory Requirements:** {len(regulatory_gaps)} gaps ({reg_percentage:.1f}%)")
    
    # Business impact distribution
    business_impact_groups = {
        'high': [g for g in compliance_gaps if _get_gap_value(g, 'business_impact', 'medium') == 'high'],
        'medium': [g for g in compliance_gaps if _get_gap_value(g, 'business_impact', 'medium') == 'medium'],
        'low': [g for g in compliance_gaps if _get_gap_value(g, 'business_impact', 'medium') == 'low']
    }
    
    analysis_parts.append("\n**Business Impact Distribution:**")
    for impact_level, gaps in business_impact_groups.items():
        if gaps:
            percentage = (len(gaps) / total_gaps) * 100
            analysis_parts.append(f"- **{impact_level.title()} Impact:** {len(gaps)} gaps ({percentage:.1f}%)")
    
    return "\n".join(analysis_parts)

def _build_control_family_analysis(compliance_gaps: List[Union[Dict[str, Any], ComplianceGap]]) -> str:
    """Build ISO27001 control family analysis."""
    
    if not compliance_gaps:
        return "**No control family gaps identified.**"
    
    analysis_parts = []
    
    # Map gaps to ISO27001 control families
    control_families = {
        'A.5 - Information Security Policies': [],
        'A.6 - Organization of Information Security': [],
        'A.7 - Human Resource Security': [],
        'A.8 - Asset Management': [],
        'A.9 - Access Control': [],
        'A.10 - Cryptography': [],
        'A.11 - Physical and Environmental Security': [],
        'A.12 - Operations Security': [],
        'A.13 - Communications Security': [],
        'A.14 - System Acquisition, Development and Maintenance': [],
        'A.15 - Supplier Relationships': [],
        'A.16 - Information Security Incident Management': [],
        'A.17 - Information Security Aspects of Business Continuity Management': [],
        'A.18 - Compliance': []
    }
    
    # Categorize gaps by control families (simplified mapping)
    for gap in compliance_gaps:
        gap_category = _get_gap_value(gap, 'gap_category', 'other').lower()
        gap_title = _get_gap_value(gap, 'gap_title', 'Unknown Gap')
        risk_level = _get_gap_value(gap, 'risk_level', 'medium')
        
        # Map categories to control families
        if 'access' in gap_category or 'authentication' in gap_category:
            control_families['A.9 - Access Control'].append({'title': gap_title, 'risk': risk_level})
        elif 'encryption' in gap_category or 'crypto' in gap_category:
            control_families['A.10 - Cryptography'].append({'title': gap_title, 'risk': risk_level})
        elif 'network' in gap_category or 'communication' in gap_category:
            control_families['A.13 - Communications Security'].append({'title': gap_title, 'risk': risk_level})
        elif 'incident' in gap_category or 'response' in gap_category:
            control_families['A.16 - Information Security Incident Management'].append({'title': gap_title, 'risk': risk_level})
        elif 'backup' in gap_category or 'continuity' in gap_category:
            control_families['A.17 - Information Security Aspects of Business Continuity Management'].append({'title': gap_title, 'risk': risk_level})
        elif 'compliance' in gap_category or 'audit' in gap_category:
            control_families['A.18 - Compliance'].append({'title': gap_title, 'risk': risk_level})
        elif 'asset' in gap_category or 'inventory' in gap_category:
            control_families['A.8 - Asset Management'].append({'title': gap_title, 'risk': risk_level})
        elif 'physical' in gap_category or 'facility' in gap_category:
            control_families['A.11 - Physical and Environmental Security'].append({'title': gap_title, 'risk': risk_level})
        elif 'operations' in gap_category or 'procedure' in gap_category:
            control_families['A.12 - Operations Security'].append({'title': gap_title, 'risk': risk_level})
        elif 'policy' in gap_category or 'governance' in gap_category:
            control_families['A.5 - Information Security Policies'].append({'title': gap_title, 'risk': risk_level})
        elif 'hr' in gap_category or 'human' in gap_category or 'personnel' in gap_category:
            control_families['A.7 - Human Resource Security'].append({'title': gap_title, 'risk': risk_level})
        else:
            control_families['A.6 - Organization of Information Security'].append({'title': gap_title, 'risk': risk_level})
    
    # Build control family analysis
    affected_families = [family for family, gaps in control_families.items() if gaps]
    total_families = len(control_families)
    
    analysis_parts.append(f"**ISO27001 Control Family Coverage:**")
    analysis_parts.append(f"- **Affected Families:** {len(affected_families)} out of {total_families} control families")
    
    if affected_families:
        analysis_parts.append("\n**Control Family Gap Distribution:**")
        
        for family_name, gaps in control_families.items():
            if gaps:
                high_risk = len([g for g in gaps if g['risk'] == 'high'])
                medium_risk = len([g for g in gaps if g['risk'] == 'medium'])
                low_risk = len([g for g in gaps if g['risk'] == 'low'])
                
                risk_breakdown = []
                if high_risk > 0:
                    risk_breakdown.append(f"High: {high_risk}")
                if medium_risk > 0:
                    risk_breakdown.append(f"Medium: {medium_risk}")
                if low_risk > 0:
                    risk_breakdown.append(f"Low: {low_risk}")
                
                analysis_parts.append(f"- **{family_name}:** {len(gaps)} gaps ({', '.join(risk_breakdown)})")
    
    return "\n".join(analysis_parts)

def _build_business_impact_analysis(compliance_gaps: List[Union[Dict[str, Any], ComplianceGap]]) -> str:
    """Build business impact analysis with financial and operational considerations."""
    
    if not compliance_gaps:
        return "**No business impact identified.**"
    
    analysis_parts = []
    
    # Financial impact analysis
    total_potential_fines = 0
    gaps_with_fines = 0
    
    for gap in compliance_gaps:
        fine_amount = _get_gap_value(gap, 'potential_fine_amount', 0)
        if fine_amount:
            if hasattr(fine_amount, '__float__'):
                fine_amount = float(fine_amount)
            total_potential_fines += fine_amount
            gaps_with_fines += 1
    
    analysis_parts.append("**Financial Impact Assessment:**")
    if total_potential_fines > 0:
        analysis_parts.append(f"- **Direct Financial Exposure:** ${total_potential_fines:,.2f}")
        analysis_parts.append(f"- **Gaps with Quantified Fines:** {gaps_with_fines} out of {len(compliance_gaps)}")
    else:
        analysis_parts.append("- **Direct Financial Exposure:** Not quantified in current gaps")
    
    # Regulatory impact
    regulatory_gaps = [g for g in compliance_gaps if _get_gap_value(g, 'regulatory_requirement', False)]
    if regulatory_gaps:
        analysis_parts.append(f"- **Regulatory Compliance Risk:** {len(regulatory_gaps)} gaps affect regulatory requirements")
        analysis_parts.append("- **Potential Consequences:** Regulatory fines, license suspension, audit findings")
    
    # Operational impact by business impact level
    high_impact_gaps = [g for g in compliance_gaps if _get_gap_value(g, 'business_impact', 'medium') == 'high']
    medium_impact_gaps = [g for g in compliance_gaps if _get_gap_value(g, 'business_impact', 'medium') == 'medium']
    
    analysis_parts.append("\n**Operational Impact Assessment:**")
    if high_impact_gaps:
        analysis_parts.append(f"- **High Impact Operations:** {len(high_impact_gaps)} gaps affect critical business functions")
        analysis_parts.append("  - Customer data protection and privacy")
        analysis_parts.append("  - Service availability and reliability")
        analysis_parts.append("  - Competitive advantage and intellectual property")
    
    if medium_impact_gaps:
        analysis_parts.append(f"- **Medium Impact Operations:** {len(medium_impact_gaps)} gaps affect important business processes")
        analysis_parts.append("  - Internal operations and efficiency")
        analysis_parts.append("  - Vendor and partner relationships")
        analysis_parts.append("  - Employee productivity and security")
    
    # Certification readiness
    total_gaps = len(compliance_gaps)
    high_risk_gaps = len([g for g in compliance_gaps if _get_gap_value(g, 'risk_level', 'medium') == 'high'])
    
    analysis_parts.append(f"\n**ISO27001 Certification Readiness:**")
    if high_risk_gaps == 0:
        analysis_parts.append("- **Readiness Status:** High - No critical gaps identified")
        analysis_parts.append("- **Estimated Timeline:** 3-6 months with current gap remediation")
    elif high_risk_gaps <= 2:
        analysis_parts.append("- **Readiness Status:** Medium-High - Limited critical gaps")
        analysis_parts.append("- **Estimated Timeline:** 6-9 months with focused remediation")
    elif high_risk_gaps <= 5:
        analysis_parts.append("- **Readiness Status:** Medium - Several critical gaps require attention")
        analysis_parts.append("- **Estimated Timeline:** 9-12 months with comprehensive remediation")
    else:
        analysis_parts.append("- **Readiness Status:** Low - Significant gaps across multiple control families")
        analysis_parts.append("- **Estimated Timeline:** 12-18 months with systematic remediation")
    
    return "\n".join(analysis_parts)

def _build_investment_priorities_analysis(compliance_gaps: List[Union[Dict[str, Any], ComplianceGap]]) -> str:
    """Build investment priorities analysis with cost-benefit considerations."""
    
    if not compliance_gaps:
        return "**No investment priorities identified.**"
    
    analysis_parts = []
    
    # Priority matrix based on risk level and business impact
    high_risk_high_impact = []
    high_risk_medium_impact = []
    medium_risk_high_impact = []
    other_priorities = []
    
    for gap in compliance_gaps:
        risk_level = _get_gap_value(gap, 'risk_level', 'medium')
        business_impact = _get_gap_value(gap, 'business_impact', 'medium')
        gap_title = _get_gap_value(gap, 'gap_title', 'Unknown Gap')
        recommendation = _get_gap_value(gap, 'recommendation_text', '')
        
        gap_info = {
            'title': gap_title,
            'risk': risk_level,
            'impact': business_impact,
            'recommendation': recommendation[:100] + "..." if len(recommendation) > 100 else recommendation
        }
        
        if risk_level == 'high' and business_impact == 'high':
            high_risk_high_impact.append(gap_info)
        elif risk_level == 'high' and business_impact == 'medium':
            high_risk_medium_impact.append(gap_info)
        elif risk_level == 'medium' and business_impact == 'high':
            medium_risk_high_impact.append(gap_info)
        else:
            other_priorities.append(gap_info)
    
    analysis_parts.append("**Investment Priority Matrix:**")
    
    # Priority 1: High risk, high impact
    if high_risk_high_impact:
        analysis_parts.append(f"\n**Priority 1 - Immediate Action Required ({len(high_risk_high_impact)} gaps):**")
        analysis_parts.append("- **Investment Urgency:** Critical - Address within 30-60 days")
        analysis_parts.append("- **Resource Allocation:** 40-50% of cybersecurity budget")
        
        for i, gap in enumerate(high_risk_high_impact[:3], 1):  # Show top 3
            analysis_parts.append(f"\n{i}. **{gap['title']}**")
            if gap['recommendation']:
                analysis_parts.append(f"   - *Quick Win:* {gap['recommendation']}")
    
    # Priority 2: High risk, medium impact or medium risk, high impact
    priority_2_gaps = high_risk_medium_impact + medium_risk_high_impact
    if priority_2_gaps:
        analysis_parts.append(f"\n**Priority 2 - Strategic Implementation ({len(priority_2_gaps)} gaps):**")
        analysis_parts.append("- **Investment Urgency:** High - Address within 60-120 days")
        analysis_parts.append("- **Resource Allocation:** 30-35% of cybersecurity budget")
        
        for i, gap in enumerate(priority_2_gaps[:3], 1):  # Show top 3
            analysis_parts.append(f"\n{i}. **{gap['title']}**")
            if gap['recommendation']:
                analysis_parts.append(f"   - *Implementation:* {gap['recommendation']}")
    
    # Priority 3: Other gaps
    if other_priorities:
        analysis_parts.append(f"\n**Priority 3 - Planned Improvements ({len(other_priorities)} gaps):**")
        analysis_parts.append("- **Investment Urgency:** Medium - Address within 3-6 months")
        analysis_parts.append("- **Resource Allocation:** 15-25% of cybersecurity budget")
    
    # Cost-benefit analysis
    analysis_parts.append(f"\n**Cost-Benefit Analysis:**")
    
    # Estimate investment levels
    total_gaps = len(compliance_gaps)
    high_priority_count = len(high_risk_high_impact) + len(priority_2_gaps)
    
    if total_gaps <= 5:
        analysis_parts.append("- **Estimated Investment:** $50K-$150K over 6-12 months")
        analysis_parts.append("- **ROI Timeline:** 12-18 months")
    elif total_gaps <= 10:
        analysis_parts.append("- **Estimated Investment:** $150K-$300K over 9-15 months")
        analysis_parts.append("- **ROI Timeline:** 18-24 months")
    else:
        analysis_parts.append("- **Estimated Investment:** $300K-$500K over 12-24 months")
        analysis_parts.append("- **ROI Timeline:** 24-36 months")
    
    analysis_parts.append("- **Risk Reduction Benefits:**")
    analysis_parts.append("  - Reduced regulatory fine exposure")
    analysis_parts.append("  - Lower cyber insurance premiums")
    analysis_parts.append("  - Improved customer trust and retention")
    analysis_parts.append("  - Enhanced competitive positioning")
    
    return "\n".join(analysis_parts)

def _create_control_risk_prioritization_prompt(
    audit_context: str,
    control_gaps_analysis: str,
    control_family_analysis: str,
    business_impact_analysis: str,
    investment_priorities: str,
) -> tuple[str, str]:
    """Create the OpenAI prompt for control risk prioritization analysis."""
    
    # System message to set the CISO/executive business intelligence context
    system_message = (
        "You are an expert cybersecurity consultant and business strategist specializing in "
        "executive-level risk assessments for IT organizations. Generate professional, "
        "board-ready control risk prioritization analyses that translate technical compliance "
        "gaps into business-focused recommendations. Focus on strategic decision-making, "
        "investment priorities, competitive positioning, and regulatory implications. "
        "Use clear executive language suitable for C-level executives and board members. "
        "Format responses in clean markdown with appropriate headers and bullet points."
    )
    
    user_prompt = f"""
Please generate a comprehensive control risk prioritization analysis for the following IT organization compliance audit.

## Audit Context
{audit_context}

## Control Gaps Analysis
{control_gaps_analysis}

## ISO27001 Control Family Analysis
{control_family_analysis}

## Business Impact Analysis
{business_impact_analysis}

## Investment Priorities Analysis
{investment_priorities}

## Analysis Requirements
Generate a professional CISO/Board-ready summary with cybersecurity business intelligence covering:

1. **Executive Summary** - Overall cybersecurity risk posture and business implications
2. **Critical Control Gaps** - Most significant gaps and their threat exposure to the business
3. **Certification Readiness Assessment** - ISO27001 readiness status and realistic timeline
4. **Strategic Investment Priorities** - Resource allocation for maximum risk reduction and ROI
5. **Regulatory Compliance Implications** - GDPR, sector-specific requirements, and compliance risks
6. **Competitive Analysis** - How control gaps affect competitive advantage/disadvantage
7. **Board-Level Recommendations** - Specific, actionable strategic decisions for executive leadership

## Output Format
- Professional markdown suitable for C-level presentation and board reporting
- Focus on business impact and strategic decision-making rather than technical details
- Include quantified risks and investment recommendations where possible
- Prioritize recommendations based on business value and regulatory requirements
- Length: 1200-1800 words
- Use executive summary format with clear, actionable insights

Generate the control risk prioritization analysis now.
"""
    
    return system_message, user_prompt