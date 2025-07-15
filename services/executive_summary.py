import logging
from typing import Dict, List, Any
from fastapi import HTTPException
from openai import OpenAI
from config.config import settings

logger = logging.getLogger(__name__)

def generate_executive_summary(
    audit_report: Dict[str, Any],
    compliance_gaps: List[Dict[str, Any]],
    summary_type: str = "standard",
    custom_instructions: str = None
) -> str:
    """
    Generate an executive summary using OpenAI API based on audit report and compliance gaps.
    
    Args:
        audit_report: Full audit report object with all metadata
        compliance_gaps: List of compliance gap objects
        summary_type: Type of summary to generate (standard, detailed, brief)
        custom_instructions: Optional custom instructions for the summary generation
    
    Returns:
        Formatted markdown executive summary
    """
    
    # Build context from audit report
    audit_context = _build_audit_context(audit_report)
    
    # Build compliance gaps analysis
    gaps_analysis = _build_gaps_analysis(compliance_gaps)
    
    # Build summary statistics
    summary_stats = _build_summary_statistics(audit_report, compliance_gaps)
    
    # Create the prompt based on summary type
    prompt = _create_summary_prompt(
        audit_context, 
        gaps_analysis, 
        summary_stats, 
        summary_type,
        custom_instructions
    )
    
    client = OpenAI(api_key=settings.openai_api_key)
    
    try:
        completion = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert compliance analyst and executive report writer. "
                        "Generate professional, concise, and actionable executive summaries "
                        "for compliance audit reports. Use clear business language suitable "
                        "for C-level executives and compliance teams. Format responses in "
                        "clean markdown with appropriate headers and bullet points."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,  # Lower temperature for more consistent, professional output
            max_tokens=2000,  # Adjust based on desired summary length
        )
    except Exception as e:
        logger.error("OpenAI ChatCompletion failed for executive summary", exc_info=True)
        raise HTTPException(status_code=502, detail=f"OpenAI API error: {e}")
    
    summary = completion.choices[0].message.content.strip()
    
    logger.info(f"Successfully generated executive summary for audit report "
               f"'{audit_report.get('report_title', 'Unknown')}' with {len(compliance_gaps)} gaps")
    
    return summary


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


def _build_gaps_analysis(compliance_gaps: List[Dict[str, Any]]) -> str:
    """Build compliance gaps analysis section."""
    
    if not compliance_gaps:
        return "**No compliance gaps identified in this audit.**"
    
    analysis_parts = []
    
    # Group gaps by risk level
    risk_groups = {}
    for gap in compliance_gaps:
        risk_level = gap.get('risk_level', 'unknown')
        if risk_level not in risk_groups:
            risk_groups[risk_level] = []
        risk_groups[risk_level].append(gap)
    
    # Group gaps by category
    category_groups = {}
    for gap in compliance_gaps:
        category = gap.get('gap_category', 'uncategorized')
        if category not in category_groups:
            category_groups[category] = []
        category_groups[category].append(gap)
    
    # Risk level breakdown
    analysis_parts.append("**Risk Level Distribution:**")
    for risk_level in ['high', 'medium', 'low']:
        count = len(risk_groups.get(risk_level, []))
        if count > 0:
            analysis_parts.append(f"- {risk_level.title()}: {count} gaps")
    
    # Category breakdown
    analysis_parts.append("\n**Gap Categories:**")
    for category, gaps in category_groups.items():
        analysis_parts.append(f"- {category}: {len(gaps)} gaps")
    
    # Regulatory requirements
    regulatory_gaps = [gap for gap in compliance_gaps if gap.get('regulatory_requirement', False)]
    if regulatory_gaps:
        analysis_parts.append(f"\n**Regulatory Requirements:** {len(regulatory_gaps)} gaps require regulatory compliance")
    
    # Financial impact
    total_potential_fines = sum(gap.get('potential_fine_amount', 0) for gap in compliance_gaps)
    if total_potential_fines > 0:
        analysis_parts.append(f"**Potential Financial Impact:** ${total_potential_fines:,.2f}")
    
    return "\n".join(analysis_parts)


def _build_summary_statistics(audit_report: Dict[str, Any], compliance_gaps: List[Dict[str, Any]]) -> str:
    """Build summary statistics section."""
    
    stats_parts = []
    
    # Overall audit metrics
    total_gaps = len(compliance_gaps)
    stats_parts.append(f"**Total Compliance Gaps:** {total_gaps}")
    
    # Confidence metrics
    if compliance_gaps:
        avg_confidence = sum(gap.get('confidence_score', 0) for gap in compliance_gaps) / len(compliance_gaps)
        stats_parts.append(f"**Average Confidence Score:** {avg_confidence:.2f}")
        
        avg_false_positive = sum(gap.get('false_positive_likelihood', 0) for gap in compliance_gaps) / len(compliance_gaps)
        stats_parts.append(f"**Average False Positive Likelihood:** {avg_false_positive:.2f}")
    
    # Detection methods
    detection_methods = {}
    for gap in compliance_gaps:
        method = gap.get('detection_method', 'unknown')
        detection_methods[method] = detection_methods.get(method, 0) + 1
    
    if detection_methods:
        stats_parts.append("**Detection Methods:**")
        for method, count in detection_methods.items():
            stats_parts.append(f"- {method}: {count} gaps")
    
    return "\n".join(stats_parts)


def _create_summary_prompt(
    audit_context: str,
    gaps_analysis: str,
    summary_stats: str,
    summary_type: str,
    custom_instructions: str = None
) -> str:
    """Create the OpenAI prompt for executive summary generation."""
    
    base_prompt = f"""
Please generate a professional executive summary for the following compliance audit report.

## Audit Context
{audit_context}

## Compliance Gaps Analysis
{gaps_analysis}

## Summary Statistics
{summary_stats}

## Summary Requirements
- Format: Professional markdown suitable for executive presentation
- Tone: Clear, concise, business-focused
- Include: Key findings, risk assessment, actionable recommendations
- Structure: Executive overview, key findings, risk prioritization, next steps
"""

    # Add summary type specific instructions
    type_instructions = {
        "standard": "Create a comprehensive executive summary (800-1200 words) covering all key aspects.",
        "brief": "Create a concise executive summary (300-500 words) focusing on critical findings only.",
        "detailed": "Create a detailed executive summary (1200-2000 words) with in-depth analysis and recommendations."
    }
    
    base_prompt += f"\n- Length: {type_instructions.get(summary_type, type_instructions['standard'])}"
    
    # Add custom instructions if provided
    if custom_instructions:
        base_prompt += f"\n- Additional Instructions: {custom_instructions}"
    
    base_prompt += """

Generate the executive summary now, using clear markdown formatting with appropriate headers and bullet points.
"""
    
    return base_prompt