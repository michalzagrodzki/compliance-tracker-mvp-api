import logging
from typing import Dict, Any
from fastapi import HTTPException
from openai import OpenAI
from config.config import settings

logger = logging.getLogger(__name__)

def generate_compliance_recommendation(
    chat_history_item: Dict[str, Any],
    recommendation_type: str,
) -> str:
    """
    Generate a detailed compliance recommendation using OpenAI API based on chat history context
    and specified recommendation type.
    
    Args:
        chat_history_item: Full chat history item with question, answer, and metadata
        recommendation_type: Type of recommendation to generate (create_policy, update_policy, etc.)
    
    Returns:
        Formatted markdown recommendation text with implementation steps
    """
    
    # Build context from chat history item
    context = _build_chat_context(chat_history_item)
    
    # Create the prompt based on recommendation type
    system_message, user_prompt = _create_recommendation_prompt(
        context, 
        recommendation_type
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
               f"{chat_history_item.get('id', 'Unknown')}")
    
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

def _create_recommendation_prompt(
    context: str,
    recommendation_type: str,
) -> tuple[str, str]:
    """Create system message and user prompt based on recommendation type."""
    
    # Base system message
    system_message = (
        "You are an expert compliance consultant specializing in regulatory frameworks "
        "and organizational policy development. Generate practical, actionable "
        "recommendations for compliance gaps. Use clear, professional language "
        "suitable for compliance officers and management. Format responses in "
        "clean markdown with specific implementation steps."
    )
    
    # Type-specific prompts
    type_prompts = {
        "create_policy": {
            "instruction": "Create a recommendation for developing a new organizational policy",
            "focus": """
Focus on:
- Policy scope and objectives
- Key policy elements and requirements
- Stakeholder involvement and approval process
- Implementation timeline and milestones
- Monitoring and review mechanisms
- Template structure and key clauses
""",
            "output": "Provide a structured policy development plan with specific sections, responsibilities, and timelines."
        },
        
        "update_policy": {
            "instruction": "Create a recommendation for updating an existing organizational policy",
            "focus": """
Focus on:
- Specific gaps identified in current policy
- Required updates and modifications
- Version control and change management
- Stakeholder review and approval process
- Communication and training on changes
- Implementation and rollout strategy
""",
            "output": "Provide a detailed policy update plan with specific changes, rationale, and implementation steps."
        },
        
        "upload_document": {
            "instruction": "Create a recommendation for uploading or creating required documentation",
            "focus": """
Focus on:
- Specific documents needed
- Document content requirements and structure
- Compliance standards to be addressed
- Document approval and validation process
- Storage and access management
- Regular review and maintenance schedule
""",
            "output": "Provide a documentation plan with specific document types, content requirements, and management processes."
        },
        
        "training_needed": {
            "instruction": "Create a recommendation for compliance training and education",
            "focus": """
Focus on:
- Target audience and skill gaps
- Training content and learning objectives
- Delivery methods and formats
- Training schedule and frequency
- Assessment and competency validation
- Record keeping and compliance tracking
""",
            "output": "Provide a comprehensive training plan with curriculum, delivery methods, and success metrics."
        },
        
        "process_improvement": {
            "instruction": "Create a recommendation for improving compliance processes and procedures",
            "focus": """
Focus on:
- Current process gaps and inefficiencies
- Proposed process improvements
- Technology and automation opportunities
- Resource requirements and responsibilities
- Implementation phases and timeline
- Success metrics and monitoring
""",
            "output": "Provide a process improvement roadmap with specific enhancements, implementation steps, and success criteria."
        },
        
        "system_configuration": {
            "instruction": "Create a recommendation for system or technical configuration changes",
            "focus": """
Focus on:
- Technical requirements and specifications
- System configuration changes needed
- Security and access control considerations
- Testing and validation procedures
- Deployment and rollback plans
- Ongoing maintenance and monitoring
""",
            "output": "Provide a technical implementation plan with configuration details, testing procedures, and deployment strategy."
        }
    }
    
    prompt_config = type_prompts.get(recommendation_type, type_prompts["create_policy"])
    
    user_prompt = f"""
Based on the following compliance gap context, {prompt_config['instruction']}.

## Context from Compliance Analysis
{context}

## Recommendation Requirements
{prompt_config['focus']}

## Expected Output
{prompt_config['output']}

## Output Format
Structure your recommendation using the following markdown format:

# Recommendation: [Brief Title]

## Executive Summary
[2-3 sentence overview of the recommendation]

## Gap Analysis
[Specific compliance gap this addresses]

## Recommended Solution
[Detailed description of the recommended approach]

## Implementation Steps
1. [Step 1 with timeline]
2. [Step 2 with timeline]
3. [Continue as needed]

## Resources Required
- **Personnel:** [Roles and time commitment]
- **Technology:** [Systems or tools needed]
- **Budget:** [Estimated costs if applicable]

## Success Criteria
- [Measurable outcome 1]
- [Measurable outcome 2]
- [Continue as needed]

## Risk Mitigation
[Potential risks and mitigation strategies]

## Next Steps
[Immediate actions to initiate this recommendation]

Generate the recommendation now, ensuring it's specific, actionable, and directly addresses the compliance gap identified in the context.
"""
    
    return system_message, user_prompt