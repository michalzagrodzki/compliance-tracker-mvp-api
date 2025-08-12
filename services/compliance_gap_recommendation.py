import logging
from typing import Dict, Any, Optional
from fastapi import HTTPException
from openai import OpenAI
from config.config import settings

logger = logging.getLogger(__name__)

def generate_compliance_recommendation(
    chat_history_item: Dict[str, Any],
    recommendation_type: str,
    iso_control: Optional[str] = None,
) -> str:
    """
    Generate a detailed compliance recommendation using OpenAI API based on chat history context,
    specified recommendation type, and ISO control information.
    
    Args:
        chat_history_item: Full chat history item with question, answer, and metadata
        recommendation_type: Type of recommendation to generate (create_policy, update_policy, etc.)
        iso_control: Optional ISO 27001 control identifier (e.g., "A.8.1.1")
    
    Returns:
        Formatted markdown recommendation text with implementation steps
    """
    
    # Build context from chat history item
    context = _build_chat_context(chat_history_item)
    
    # Add ISO control context if available
    iso_context = _build_iso_control_context(iso_control) if iso_control else ""
    
    # Create the prompt based on recommendation type and ISO control
    system_message, user_prompt = _create_recommendation_prompt(
        context, 
        recommendation_type,
        iso_context
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
            max_tokens=1500,
        )
    except Exception as e:
        logger.error("OpenAI ChatCompletion failed for compliance recommendation", exc_info=True)
        raise HTTPException(status_code=502, detail=f"OpenAI API error: {e}")
    
    recommendation = completion.choices[0].message.content.strip()
    
    logger.info(f"Successfully generated {recommendation_type} recommendation for chat history ID "
               f"{chat_history_item.get('id', 'Unknown')}"
               f"{f' with ISO control {iso_control}' if iso_control else ''}")
    
    return recommendation

def _build_chat_context(chat_history_item: Dict[str, Any]) -> str:
    """Build context section from chat history item data."""
    
    context_parts = []
    
    # Basic information
    context_parts.append(f"**Original Question:** {chat_history_item.get('question', 'N/A')}")
    context_parts.append(f"**AI Answer:** {chat_history_item.get('answer', 'N/A')}")
    context_parts.append(f"**Compliance Domain:** {chat_history_item.get('compliance_domain', 'N/A')}")
    
    # Technical details from metadata
    metadata = chat_history_item.get('metadata', {})
    if metadata:
        if 'best_match_score' in metadata:
            context_parts.append(f"**Best Match Score:** {metadata['best_match_score']}")
        
        if 'source_document_count' in metadata or 'total_documents_retrieved' in metadata:
            doc_count = metadata.get('total_documents_retrieved', metadata.get('source_document_count', 0))
            context_parts.append(f"**Source Documents Retrieved:** {doc_count}")
        
        if 'document_details' in metadata and isinstance(metadata['document_details'], list):
            context_parts.append(f"**Referenced Documents:** {len(metadata['document_details'])} documents")
            
            # Add top 3 most relevant documents
            docs = metadata['document_details'][:3]
            context_parts.append("**Top Referenced Documents:**")
            for i, doc in enumerate(docs, 1):
                title = doc.get('title', 'Unknown')
                filename = doc.get('source_filename', 'Unknown')
                similarity = doc.get('similarity', 0)
                page = doc.get('source_page_number', 'N/A')
                context_parts.append(f"  {i}. {title} ({filename}, Page {page}, Similarity: {similarity:.3f})")
        
        if 'compliance_summary' in metadata:
            comp_summary = metadata['compliance_summary']
            if 'document_types' in comp_summary:
                context_parts.append(f"**Document Types:** {', '.join(comp_summary['document_types'])}")
            if 'regulatory_tags' in comp_summary:
                context_parts.append(f"**Regulatory Tags:** {', '.join(comp_summary['regulatory_tags'])}")
    
    # Source document IDs if available
    source_docs = chat_history_item.get('source_document_ids', [])
    if source_docs:
        context_parts.append(f"**Source Document IDs:** {len(source_docs)} documents referenced")
    
    return "\n".join(context_parts)

def _build_iso_control_context(iso_control: str) -> str:
    """Build ISO 27001 control-specific context from control identifier."""
    
    if not iso_control:
        return ""
    
    context_parts = []
    context_parts.append(f"**ISO 27001 Control:** {iso_control}")
    
    # Add control family information
    control_family = _get_control_family_info(iso_control)
    if control_family:
        context_parts.append(f"**Control Family:** {control_family['name']}")
        context_parts.append(f"**Control Objective:** {control_family['objective']}")
        context_parts.append(f"**Typical Evidence Types:** {', '.join(control_family['evidence_types'])}")
        context_parts.append(f"**Implementation Priority:** {control_family['risk_weight']}")
        
        if control_family.get('related_controls'):
            context_parts.append(f"**Related Controls:** {', '.join(control_family['related_controls'])}")
        
        if control_family.get('common_gaps'):
            context_parts.append(f"**Common Implementation Gaps:** {', '.join(control_family['common_gaps'])}")
    
    return "\n".join(context_parts)

def _get_control_family_info(iso_control: str) -> Optional[Dict[str, Any]]:
    """Get control family information for ISO 27001 controls."""
    
    # Extract control family from control ID (e.g., "A.8.1.1" -> "A.8")
    if not iso_control or not iso_control.startswith('A.'):
        return None
    
    try:
        control_family = iso_control.split('.')[0] + '.' + iso_control.split('.')[1]
    except IndexError:
        return None
    
    # ISO 27001:2022 control families
    control_families = {
        "A.5": {
            "name": "Organizational Controls",
            "objective": "Establish information security governance and management framework",
            "evidence_types": ["Policies", "Procedures", "Management Reviews", "Training Records"],
            "related_controls": ["A.6", "A.7"],
            "risk_weight": "high",
            "common_gaps": ["Missing policy approvals", "Outdated procedures", "Incomplete training"]
        },
        "A.6": {
            "name": "People Controls", 
            "objective": "Ensure personnel understand security responsibilities",
            "evidence_types": ["Job Descriptions", "Training Records", "Background Checks", "NDAs"],
            "related_controls": ["A.5", "A.7"],
            "risk_weight": "high",
            "common_gaps": ["Missing background checks", "Incomplete role definitions", "No confidentiality agreements"]
        },
        "A.7": {
            "name": "Physical and Environmental Controls",
            "objective": "Protect physical and environmental security",
            "evidence_types": ["Site Plans", "Access Logs", "Environmental Monitoring", "Disposal Records"],
            "related_controls": ["A.8", "A.11"],
            "risk_weight": "medium",
            "common_gaps": ["Inadequate visitor controls", "Missing disposal procedures", "No environmental monitoring"]
        },
        "A.8": {
            "name": "Technology Controls",
            "objective": "Ensure secure technology management and configuration",
            "evidence_types": ["Asset Inventories", "Configuration Baselines", "Vulnerability Scans", "Change Records"],
            "related_controls": ["A.9", "A.12", "A.13"],
            "risk_weight": "high",
            "common_gaps": ["Incomplete asset inventory", "Missing configuration management", "No vulnerability management"]
        },
        "A.9": {
            "name": "Access Control",
            "objective": "Control access to information and systems",
            "evidence_types": ["Access Control Lists", "User Accounts", "Access Reviews", "Privilege Management"],
            "related_controls": ["A.6", "A.8"],
            "risk_weight": "high",
            "common_gaps": ["Excessive privileges", "Missing access reviews", "No segregation of duties"]
        },
        "A.10": {
            "name": "Cryptography",
            "objective": "Ensure proper use of cryptography to protect information",
            "evidence_types": ["Encryption Policies", "Key Management", "Cryptographic Controls", "Algorithm Specifications"],
            "related_controls": ["A.8", "A.13"],
            "risk_weight": "high",
            "common_gaps": ["Weak encryption", "Poor key management", "Outdated algorithms"]
        },
        "A.11": {
            "name": "Operations Security",
            "objective": "Ensure correct and secure operations of information processing facilities",
            "evidence_types": ["Operating Procedures", "Change Management", "Capacity Management", "Backup Procedures"],
            "related_controls": ["A.7", "A.12", "A.17"],
            "risk_weight": "medium",
            "common_gaps": ["Missing procedures", "No change control", "Inadequate backups"]
        },
        "A.12": {
            "name": "Communications Security",
            "objective": "Protect information in networks and information processing facilities",
            "evidence_types": ["Network Security Controls", "Data Transfer Procedures", "Network Monitoring", "Secure Protocols"],
            "related_controls": ["A.8", "A.10", "A.13"],
            "risk_weight": "high",
            "common_gaps": ["Unencrypted communications", "Missing network segmentation", "No data transfer controls"]
        },
        "A.13": {
            "name": "System Acquisition, Development and Maintenance",
            "objective": "Ensure information security is designed and implemented within development lifecycle",
            "evidence_types": ["Development Standards", "Security Testing", "Code Reviews", "System Documentation"],
            "related_controls": ["A.8", "A.12"],
            "risk_weight": "medium",
            "common_gaps": ["No security testing", "Missing secure coding standards", "Inadequate documentation"]
        },
        "A.14": {
            "name": "Supplier Relationships",
            "objective": "Ensure protection of organization's assets accessible by suppliers",
            "evidence_types": ["Supplier Agreements", "Security Requirements", "Supplier Assessments", "Service Level Agreements"],
            "related_controls": ["A.5", "A.15"],
            "risk_weight": "medium",
            "common_gaps": ["Missing security clauses", "No supplier assessments", "Inadequate monitoring"]
        },
        "A.15": {
            "name": "Information Security Incident Management",
            "objective": "Ensure consistent and effective approach to information security incident management",
            "evidence_types": ["Incident Procedures", "Incident Reports", "Response Teams", "Lessons Learned"],
            "related_controls": ["A.16", "A.17"],
            "risk_weight": "high",
            "common_gaps": ["No incident response plan", "Missing escalation procedures", "Inadequate logging"]
        },
        "A.16": {
            "name": "Information Security in Project Management",
            "objective": "Ensure information security is addressed in project management",
            "evidence_types": ["Project Security Requirements", "Security Reviews", "Project Documentation"],
            "related_controls": ["A.5", "A.13"],
            "risk_weight": "medium",
            "common_gaps": ["Missing security requirements", "No security reviews", "Inadequate documentation"]
        },
        "A.17": {
            "name": "Information Security Aspects of Business Continuity Management",
            "objective": "Information security continuity shall be embedded in organization's business continuity management systems",
            "evidence_types": ["Continuity Plans", "Recovery Procedures", "Testing Records", "Impact Assessments"],
            "related_controls": ["A.11", "A.15"],
            "risk_weight": "high",
            "common_gaps": ["No continuity planning", "Missing recovery procedures", "Inadequate testing"]
        },
        "A.18": {
            "name": "Compliance",
            "objective": "Avoid breaches of legal, statutory, regulatory or contractual obligations",
            "evidence_types": ["Legal Reviews", "Compliance Reports", "Audit Records", "Regulatory Mappings"],
            "related_controls": ["A.5", "A.15"],
            "risk_weight": "high",
            "common_gaps": ["Missing legal reviews", "No compliance monitoring", "Inadequate documentation"]
        }
    }
    
    return control_families.get(control_family)

def _create_recommendation_prompt(
    context: str,
    recommendation_type: str,
    iso_context: str = "",
) -> tuple[str, str]:
    """Create system message and user prompt based on recommendation type and ISO control."""
    
    # Enhanced system message with ISO 27001 context
    if iso_context:
        system_message = (
            "You are an expert ISO 27001 compliance consultant specializing in information "
            "security management systems (ISMS) and regulatory frameworks. Generate practical, "
            "actionable recommendations that directly align with ISO 27001:2022 control requirements. "
            "Use clear, professional language suitable for compliance officers, information "
            "security managers, and audit teams. Format responses in clean markdown with "
            "specific implementation steps that will satisfy auditor expectations and ensure "
            "control compliance."
        )
    else:
        system_message = (
            "You are an expert compliance consultant specializing in regulatory frameworks "
            "and organizational policy development. Generate practical, actionable "
            "recommendations for compliance gaps. Use clear, professional language "
            "suitable for compliance officers and management. Format responses in "
            "clean markdown with specific implementation steps."
        )
    
    # Type-specific prompts with ISO control enhancement
    iso_enhancement = ""
    if iso_context:
        iso_enhancement = f"""

## ISO 27001 Control Context
{iso_context}

**Critical Requirements**: Ensure your recommendation specifically addresses the requirements of this ISO 27001 control:
- Reference the control number and family in your recommendation
- Align implementation with control objectives and evidence requirements
- Include appropriate audit evidence collection strategies
- Consider impact on related controls
- Set implementation timeline based on control risk priority
- Address common implementation gaps for this control family
"""

    # Type-specific prompts
    type_prompts = {
        "create_policy": {
            "instruction": "Create a recommendation for developing a new organizational policy" + (" that satisfies the specified ISO 27001 control requirements" if iso_context else ""),
            "focus": f"""
Focus on:
- Policy scope and objectives{'aligned with ISO control requirements' if iso_context else ''}
- Key policy elements {'mandated by the control' if iso_context else 'required for compliance'}
- {'Control-specific implementation guidance and evidence requirements' if iso_context else 'Implementation guidance and compliance requirements'}
- Stakeholder involvement {'including information security team' if iso_context else 'and approval process'}
- Implementation timeline {'considering control criticality' if iso_context else 'and milestones'}
- Monitoring and review mechanisms {'for continuous compliance' if iso_context else ''}
- Template structure {'incorporating ISO 27001 control language' if iso_context else 'and key clauses'}
{iso_enhancement}""",
            "output": "Provide a structured policy development plan with" + (" ISO 27001 control alignment," if iso_context else "") + " specific sections, responsibilities, and" + (" audit-ready" if iso_context else "") + " timelines."
        },
        
        "update_policy": {
            "instruction": "Create a recommendation for updating an existing organizational policy" + (" to meet ISO 27001 control requirements" if iso_context else ""),
            "focus": f"""
Focus on:
- Specific gaps identified in current policy{'relative to ISO control requirements' if iso_context else ''}
- Required updates and modifications{'to achieve control compliance' if iso_context else ''}
- {'Control-specific evidence and implementation requirements' if iso_context else 'Implementation requirements'}
- Version control and change management
- Stakeholder review and approval process{'including security team' if iso_context else ''}
- Communication and training on changes
- Implementation and rollout strategy{'with audit considerations' if iso_context else ''}
{iso_enhancement}""",
            "output": "Provide a detailed policy update plan with specific changes, rationale, and implementation steps" + (" that will satisfy audit requirements." if iso_context else ".")
        },
        
        "upload_document": {
            "instruction": "Create a recommendation for uploading or creating required documentation" + (" for ISO 27001 control compliance" if iso_context else ""),
            "focus": f"""
Focus on:
- Specific documents needed{'for control evidence' if iso_context else ''}
- Document content requirements and structure{'per ISO standards' if iso_context else ''}
- {'ISO control compliance requirements to be addressed' if iso_context else 'Compliance standards to be addressed'}
- Document approval and validation process
- Storage and access management{'with proper security controls' if iso_context else ''}
- Regular review and maintenance schedule{'for audit readiness' if iso_context else ''}
{iso_enhancement}""",
            "output": "Provide a documentation plan with specific document types, content requirements, and management processes" + (" that will satisfy audit evidence requirements." if iso_context else ".")
        },
        
        "training_needed": {
            "instruction": "Create a recommendation for compliance training and education" + (" focused on ISO 27001 control requirements" if iso_context else ""),
            "focus": f"""
Focus on:
- Target audience and skill gaps{'related to control implementation' if iso_context else ''}
- Training content and learning objectives{'aligned with control requirements' if iso_context else ''}
- {'ISO control-specific competency requirements' if iso_context else 'Competency requirements'}
- Delivery methods and formats
- Training schedule and frequency{'considering control criticality' if iso_context else ''}
- Assessment and competency validation{'for audit purposes' if iso_context else ''}
- Record keeping and compliance tracking
{iso_enhancement}""",
            "output": "Provide a comprehensive training plan with curriculum, delivery methods, and success metrics" + (" that demonstrates control competency." if iso_context else ".")
        },
        
        "process_improvement": {
            "instruction": "Create a recommendation for improving compliance processes and procedures" + (" to meet ISO 27001 control objectives" if iso_context else ""),
            "focus": f"""
Focus on:
- Current process gaps and inefficiencies{'affecting control implementation' if iso_context else ''}
- Proposed process improvements{'aligned with control requirements' if iso_context else ''}
- {'Control-specific implementation and monitoring requirements' if iso_context else 'Implementation and monitoring requirements'}
- Technology and automation opportunities
- Resource requirements and responsibilities{'including security roles' if iso_context else ''}
- Implementation phases and timeline{'based on control priority' if iso_context else ''}
- Success metrics and monitoring{'for audit compliance' if iso_context else ''}
{iso_enhancement}""",
            "output": "Provide a process improvement roadmap with specific enhancements, implementation steps, and success criteria" + (" that ensure control effectiveness." if iso_context else ".")
        },
        
        "system_configuration": {
            "instruction": "Create a recommendation for system or technical configuration changes" + (" to implement ISO 27001 control requirements" if iso_context else ""),
            "focus": f"""
Focus on:
- Technical requirements and specifications{'for control implementation' if iso_context else ''}
- System configuration changes needed{'to meet control objectives' if iso_context else ''}
- {'Control-specific security and access control requirements' if iso_context else 'Security and access control considerations'}
- Testing and validation procedures{'for audit evidence' if iso_context else ''}
- Deployment and rollback plans
- Ongoing maintenance and monitoring{'for continuous compliance' if iso_context else ''}
{iso_enhancement}""",
            "output": "Provide a technical implementation plan with configuration details, testing procedures, and deployment strategy" + (" that satisfies control requirements." if iso_context else ".")
        }
    }
    
    prompt_config = type_prompts.get(recommendation_type, type_prompts["create_policy"])
    
    user_prompt = f"""
Based on the following compliance gap context{'and ISO 27001 control requirements' if iso_context else ''}, {prompt_config['instruction']}.

## Context from Compliance Analysis
{context}
{iso_enhancement}

## Recommendation Requirements
{prompt_config['focus']}

## Expected Output
{prompt_config['output']}

## Output Format
Structure your recommendation using the following markdown format:

# Recommendation: [Brief Title{'with ISO Control Reference' if iso_context else ''}]

## Executive Summary
[2-3 sentence overview of the recommendation{'and control alignment' if iso_context else ''}]

## Gap Analysis
[Specific compliance gap this addresses{'and control requirements not met' if iso_context else ''}]

## Recommended Solution
[Detailed description of the recommended approach{'aligned with control objectives' if iso_context else ''}]

## Implementation Steps
1. [Step 1 with timeline{'and control requirements' if iso_context else ''}]
2. [Step 2 with timeline{'and control requirements' if iso_context else ''}]
3. [Continue as needed]

## Resources Required
- **Personnel:** [Roles and time commitment{'including security responsibilities' if iso_context else ''}]
- **Technology:** [Systems or tools needed{'for control implementation' if iso_context else ''}]
- **Budget:** [Estimated costs if applicable]

## Success Criteria
- [Measurable outcome 1{'with audit evidence' if iso_context else ''}]
- [Measurable outcome 2{'with audit evidence' if iso_context else ''}]
- [Continue as needed]

## Risk Mitigation
[Potential risks and mitigation strategies{'including control failure risks' if iso_context else ''}]

## Next Steps
[Immediate actions to initiate this recommendation{'with control implementation priorities' if iso_context else ''}]

Generate the recommendation now, ensuring it's specific, actionable, and {'directly addresses the ISO 27001 control requirements identified in the context' if iso_context else 'directly addresses the compliance gap identified in the context'}.
"""
    
    return system_message, user_prompt