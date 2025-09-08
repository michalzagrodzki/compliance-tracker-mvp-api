"""
Threat Intelligence service as a DI-friendly class.
"""

from typing import Dict, List, Any, Union
from fastapi import HTTPException
from openai import OpenAI

from common.logging import get_logger
from config.config import settings
from services.schemas import ComplianceGap

logger = get_logger("threat_intelligence_service")


class ThreatIntelligenceService:
    """Service to generate threat intelligence analysis via OpenAI."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or settings.openai_api_key
        self.model = model or settings.openai_model

    def generate_threat_intelligence(
        self,
        audit_report: Dict[str, Any],
        compliance_gaps: List[ComplianceGap],
    ) -> str:
        # Build context from audit report
        audit_context = _build_audit_context(audit_report)

        # Build sections
        control_gaps_analysis = _build_control_gaps_analysis(compliance_gaps)
        threat_landscape = _build_threat_landscape_analysis(compliance_gaps)
        attack_vectors = _build_attack_vector_analysis(compliance_gaps)

        # Prompt
        system_message, user_prompt = _create_threat_intelligence_prompt(
            audit_context,
            control_gaps_analysis,
            threat_landscape,
            attack_vectors,
        )

        client = OpenAI(api_key=self.api_key)

        try:
            completion = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=2000,
            )
        except Exception as e:
            logger.error(
                "OpenAI ChatCompletion failed for threat intelligence analysis", exc_info=True
            )
            raise HTTPException(status_code=502, detail=f"OpenAI API error: {e}")

        analysis = completion.choices[0].message.content.strip()

        logger.info(
            "Generated threat intelligence analysis",
            extra={
                "report_title": audit_report.get("report_title", "Unknown"),
                "gaps_count": len(compliance_gaps),
            },
        )

        return analysis


# Factory for DI
def create_threat_intelligence_service() -> ThreatIntelligenceService:
    return ThreatIntelligenceService()

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
    context_parts.append(f"**Industry Sector:** IT Services")
    context_parts.append(f"**Target Audience:** {audit_report.get('target_audience', 'N/A')}")
    context_parts.append(f"**Confidentiality Level:** {audit_report.get('confidentiality_level', 'N/A')}")
    
    # Audit scope metrics
    context_parts.append(f"**Documents Reviewed:** {len(audit_report.get('document_ids', []))}")
    context_parts.append(f"**Chat Sessions:** {len(audit_report.get('chat_history_ids', []))}")
    context_parts.append(f"**PDF Sources:** {len(audit_report.get('pdf_ingestion_ids', []))}")
    
    return "\n".join(context_parts)

def _build_control_gaps_analysis(compliance_gaps: List[Union[Dict[str, Any], ComplianceGap]]) -> str:
    """Build control gaps analysis focusing on security control families."""
    
    if not compliance_gaps:
        return "**No control gaps identified in this audit.**"
    
    analysis_parts = []
    
    control_families = {
        'access_control': [],
        'information_security': [],
        'physical_security': [],
        'operational_security': [],
        'communications_security': [],
        'system_acquisition': [],
        'incident_management': [],
        'business_continuity': [],
        'compliance': [],
        'other': []
    }
    
    # Categorize gaps by control families
    for gap in compliance_gaps:
        gap_category = _get_gap_value(gap, 'gap_category', 'other').lower()
        gap_title = _get_gap_value(gap, 'gap_title', 'Unknown Gap')
        risk_level = _get_gap_value(gap, 'risk_level', 'medium')
        
        # Simple mapping logic - can be enhanced later
        if 'access' in gap_category or 'authentication' in gap_category or 'authorization' in gap_category:
            control_families['access_control'].append({'title': gap_title, 'risk': risk_level, 'category': gap_category})
        elif 'security' in gap_category or 'encryption' in gap_category or 'crypto' in gap_category:
            control_families['information_security'].append({'title': gap_title, 'risk': risk_level, 'category': gap_category})
        elif 'physical' in gap_category or 'facility' in gap_category:
            control_families['physical_security'].append({'title': gap_title, 'risk': risk_level, 'category': gap_category})
        elif 'network' in gap_category or 'communication' in gap_category:
            control_families['communications_security'].append({'title': gap_title, 'risk': risk_level, 'category': gap_category})
        elif 'incident' in gap_category or 'response' in gap_category:
            control_families['incident_management'].append({'title': gap_title, 'risk': risk_level, 'category': gap_category})
        elif 'backup' in gap_category or 'continuity' in gap_category or 'recovery' in gap_category:
            control_families['business_continuity'].append({'title': gap_title, 'risk': risk_level, 'category': gap_category})
        elif 'compliance' in gap_category or 'audit' in gap_category:
            control_families['compliance'].append({'title': gap_title, 'risk': risk_level, 'category': gap_category})
        elif 'system' in gap_category or 'development' in gap_category:
            control_families['system_acquisition'].append({'title': gap_title, 'risk': risk_level, 'category': gap_category})
        elif 'operational' in gap_category or 'procedure' in gap_category:
            control_families['operational_security'].append({'title': gap_title, 'risk': risk_level, 'category': gap_category})
        else:
            control_families['other'].append({'title': gap_title, 'risk': risk_level, 'category': gap_category})
    
    # Build control family analysis
    analysis_parts.append("**ISO27001 Control Family Gap Analysis:**")
    
    for family_name, gaps in control_families.items():
        if gaps:
            family_display = family_name.replace('_', ' ').title()
            analysis_parts.append(f"\n**{family_display} ({len(gaps)} gaps):**")
            
            # Group by risk level within family
            high_risk = [g for g in gaps if g['risk'] == 'high']
            medium_risk = [g for g in gaps if g['risk'] == 'medium']
            low_risk = [g for g in gaps if g['risk'] == 'low']
            
            if high_risk:
                analysis_parts.append(f"- **High Risk:** {len(high_risk)} gaps")
                for gap in high_risk[:3]:  # Show top 3
                    analysis_parts.append(f"  - {gap['title']}")
            
            if medium_risk:
                analysis_parts.append(f"- **Medium Risk:** {len(medium_risk)} gaps")
                for gap in medium_risk[:2]:  # Show top 2
                    analysis_parts.append(f"  - {gap['title']}")
            
            if low_risk:
                analysis_parts.append(f"- **Low Risk:** {len(low_risk)} gaps")
    
    # Control effectiveness analysis
    total_control_families = len([f for f in control_families.values() if f])
    analysis_parts.append(f"\n**Control Coverage Assessment:**")
    analysis_parts.append(f"- **Affected Control Families:** {total_control_families} out of 10 ISO27001 families")
    
    # Calculate control gap severity
    high_risk_families = len([f for f in control_families.values() if any(g['risk'] == 'high' for g in f)])
    if high_risk_families > 0:
        analysis_parts.append(f"- **Critical Control Families:** {high_risk_families} families have high-risk gaps")
    
    return "\n".join(analysis_parts)

def _build_threat_landscape_analysis(compliance_gaps: List[Union[Dict[str, Any], ComplianceGap]]) -> str:
    """Build threat landscape analysis specific to IT industry."""
    
    analysis_parts = []
    
    # IT industry specific threats
    it_threats = {
        'ransomware': 'High - Prevalent in IT sector, targets data and systems',
        'data_breach': 'High - Customer data and intellectual property at risk',
        'insider_threats': 'Medium - IT staff have elevated access privileges',
        'supply_chain_attacks': 'High - Complex vendor and software dependencies',
        'advanced_persistent_threats': 'High - Targeted attacks on IT infrastructure',
        'cloud_security_incidents': 'High - Heavy reliance on cloud services',
        'api_attacks': 'High - Extensive API usage in modern IT systems',
        'social_engineering': 'Medium - Targeting IT staff for system access',
        'ddos_attacks': 'Medium - Service availability critical for IT companies',
        'zero_day_exploits': 'High - IT systems often targets for new exploits'
    }
    
    analysis_parts.append("**IT Industry Threat Landscape:**")
    analysis_parts.append("The IT sector faces unique cybersecurity challenges due to:")
    analysis_parts.append("- High-value intellectual property and customer data")
    analysis_parts.append("- Complex, interconnected systems and dependencies")
    analysis_parts.append("- Rapid technology adoption and digital transformation")
    analysis_parts.append("- Attractive targets for nation-state and criminal actors")
    
    analysis_parts.append("\n**Primary Threat Vectors for IT Organizations:**")
    for threat, description in it_threats.items():
        threat_display = threat.replace('_', ' ').title()
        analysis_parts.append(f"- **{threat_display}:** {description}")
    
    # Map compliance gaps to threat exposure
    analysis_parts.append("\n**Gap-to-Threat Mapping:**")
    
    # Analyze gaps for threat enablement
    access_gaps = len([g for g in compliance_gaps if 'access' in _get_gap_value(g, 'gap_category', '').lower()])
    security_gaps = len([g for g in compliance_gaps if 'security' in _get_gap_value(g, 'gap_category', '').lower()])
    incident_gaps = len([g for g in compliance_gaps if 'incident' in _get_gap_value(g, 'gap_category', '').lower()])
    backup_gaps = len([g for g in compliance_gaps if 'backup' in _get_gap_value(g, 'gap_category', '').lower()])
    
    if access_gaps > 0:
        analysis_parts.append(f"- **Access Control Gaps ({access_gaps}):** Increases exposure to insider threats, credential theft, and unauthorized access")
    
    if security_gaps > 0:
        analysis_parts.append(f"- **Information Security Gaps ({security_gaps}):** Elevates risk of data breaches, ransomware, and intellectual property theft")
    
    if incident_gaps > 0:
        analysis_parts.append(f"- **Incident Response Gaps ({incident_gaps}):** Reduces ability to detect and respond to APTs, ransomware, and breach attempts")
    
    if backup_gaps > 0:
        analysis_parts.append(f"- **Business Continuity Gaps ({backup_gaps}):** Increases impact of ransomware and increases recovery time from attacks")
    
    # Threat actor analysis
    analysis_parts.append("\n**Relevant Threat Actors for IT Sector:**")
    analysis_parts.append("- **Criminal Groups:** Focus on ransomware, data theft, and financial gain")
    analysis_parts.append("- **Nation-State Actors:** Target intellectual property and strategic information")
    analysis_parts.append("- **Hacktivists:** May target high-profile IT companies for ideological reasons")
    analysis_parts.append("- **Insider Threats:** Disgruntled employees or contractors with system access")
    
    return "\n".join(analysis_parts)

def _build_attack_vector_analysis(compliance_gaps: List[Union[Dict[str, Any], ComplianceGap]]) -> str:
    """Build analysis of attack vectors enabled by identified compliance gaps."""
    
    if not compliance_gaps:
        return "**No attack vectors identified due to lack of compliance gaps.**"
    
    analysis_parts = []
    analysis_parts.append("**Attack Vector Analysis:**")
    
    # Analyze attack vectors by risk level
    high_risk_gaps = [g for g in compliance_gaps if _get_gap_value(g, 'risk_level', 'medium') == 'high']
    medium_risk_gaps = [g for g in compliance_gaps if _get_gap_value(g, 'risk_level', 'medium') == 'medium']
    
    # High-risk attack vectors
    if high_risk_gaps:
        analysis_parts.append(f"\n**Critical Attack Vectors (High Risk - {len(high_risk_gaps)} gaps):**")
        
        for gap in high_risk_gaps[:5]:  # Show top 5
            gap_title = _get_gap_value(gap, 'gap_title', 'Unknown Gap')
            gap_description = _get_gap_value(gap, 'gap_description', '')
            recommendation = _get_gap_value(gap, 'recommendation_text', '')
            
            analysis_parts.append(f"\n**{gap_title}:**")
            
            # Truncate long descriptions
            if gap_description:
                truncated_desc = gap_description[:150] + "..." if len(gap_description) > 150 else gap_description
                analysis_parts.append(f"- *Gap:* {truncated_desc}")
            
            # Add potential attack scenarios based on gap type
            analysis_parts.append(f"- *Potential Attack Scenarios:*")
            gap_lower = gap_title.lower()
            
            if 'access' in gap_lower or 'authentication' in gap_lower:
                analysis_parts.append(f"  - Credential stuffing and brute force attacks")
                analysis_parts.append(f"  - Privilege escalation through weak controls")
                analysis_parts.append(f"  - Account takeover and lateral movement")
            elif 'encryption' in gap_lower or 'crypto' in gap_lower:
                analysis_parts.append(f"  - Man-in-the-middle attacks on unencrypted channels")
                analysis_parts.append(f"  - Data interception and theft")
                analysis_parts.append(f"  - Compliance violations and regulatory fines")
            elif 'backup' in gap_lower or 'recovery' in gap_lower:
                analysis_parts.append(f"  - Ransomware with high impact due to poor recovery")
                analysis_parts.append(f"  - Extended downtime and business disruption")
                analysis_parts.append(f"  - Data loss and corruption")
            elif 'network' in gap_lower or 'firewall' in gap_lower:
                analysis_parts.append(f"  - Network intrusion and lateral movement")
                analysis_parts.append(f"  - Data exfiltration through unsecured channels")
                analysis_parts.append(f"  - Advanced persistent threat establishment")
            else:
                analysis_parts.append(f"  - Opportunistic attacks exploiting control weaknesses")
                analysis_parts.append(f"  - Increased dwell time for attackers")
                analysis_parts.append(f"  - Reduced detection and response capabilities")
            
            # Include recommendations if available
            if recommendation and len(recommendation) > 10:
                truncated_rec = recommendation[:100] + "..." if len(recommendation) > 100 else recommendation
                analysis_parts.append(f"- *Mitigation:* {truncated_rec}")
    
    # Medium-risk attack vectors summary
    if medium_risk_gaps:
        analysis_parts.append(f"\n**Secondary Attack Vectors (Medium Risk - {len(medium_risk_gaps)} gaps):**")
        analysis_parts.append("These gaps provide additional attack surface that could be exploited in combination with other vulnerabilities:")
        
        # Group medium risk gaps by category
        medium_categories = {}
        for gap in medium_risk_gaps:
            category = _get_gap_value(gap, 'gap_category', 'other')
            if category not in medium_categories:
                medium_categories[category] = 0
            medium_categories[category] += 1
        
        for category, count in medium_categories.items():
            analysis_parts.append(f"- **{category.replace('_', ' ').title()}:** {count} gaps")
    
    # Attack path analysis
    analysis_parts.append(f"\n**Multi-Stage Attack Path Potential:**")
    
    # Calculate attack complexity
    total_gaps = len(compliance_gaps)
    if total_gaps >= 5:
        analysis_parts.append("- **High Complexity:** Multiple control gaps enable sophisticated attack chains")
        analysis_parts.append("- **Defense in Depth Compromised:** Attackers have multiple vectors to achieve objectives")
    elif total_gaps >= 3:
        analysis_parts.append("- **Medium Complexity:** Some attack chain opportunities exist")
        analysis_parts.append("- **Selective Control Bypass:** Specific attack paths may be viable")
    else:
        analysis_parts.append("- **Low Complexity:** Limited attack chain opportunities")
        analysis_parts.append("- **Isolated Risks:** Individual gaps pose contained risks")
    
    # Incident probability assessment
    regulatory_gaps = len([g for g in compliance_gaps if _get_gap_value(g, 'regulatory_requirement', False)])
    if regulatory_gaps > 0:
        analysis_parts.append(f"\n**Regulatory Compliance Risk:**")
        analysis_parts.append(f"- **{regulatory_gaps} regulatory gaps** increase probability of compliance violations")
        analysis_parts.append(f"- Potential fines and legal exposure beyond security incidents")
    
    return "\n".join(analysis_parts)

def _create_threat_intelligence_prompt(
    audit_context: str,
    control_gaps_analysis: str,
    threat_landscape: str,
    attack_vectors: str,
) -> tuple[str, str]:
    """Create the OpenAI prompt for threat intelligence analysis."""
    
    # System message to set the cybersecurity threat intelligence analyst context
    system_message = (
        "You are an expert cybersecurity threat intelligence analyst specializing in "
        "enterprise risk assessment for IT organizations. Generate professional, "
        "actionable threat intelligence reports that analyze how control gaps expose "
        "organizations to current threat landscapes. Focus on realistic attack scenarios, "
        "threat actor capabilities, and prioritized security recommendations. "
        "Use clear technical language suitable for security teams and executives. "
        "Format responses in clean markdown with appropriate headers and bullet points."
    )
    
    user_prompt = f"""
Please generate a comprehensive threat intelligence analysis for the following IT organization audit findings.

## Audit Context
{audit_context}

## Control Gaps Analysis
{control_gaps_analysis}

## Threat Landscape Assessment
{threat_landscape}

## Attack Vector Analysis
{attack_vectors}

## Analysis Requirements
Generate a professional threat intelligence report covering:

1. **Executive Summary** - High-level threat exposure assessment
2. **Critical Threat Scenarios** - Most likely and impactful attack scenarios based on identified gaps
3. **Threat Actor Assessment** - Which threat actors are most likely to exploit these gaps
4. **Attack Timeline Analysis** - Probable attack progression and dwell time
5. **Impact Assessment** - Business impact of successful attacks
6. **Risk Prioritization** - Which gaps should be addressed first based on threat likelihood
7. **Tactical Recommendations** - Specific, actionable security controls to implement
8. **Threat Monitoring** - Indicators to monitor for these specific threats

## Output Format
- Professional markdown suitable for security leadership
- Focus on actionable intelligence rather than generic advice  
- Include specific threat vectors and attack techniques where relevant
- Prioritize recommendations based on threat likelihood and business impact
- Length: 1000-1500 words

Generate the threat intelligence analysis now.
"""
    
    return system_message, user_prompt
