import logging
from typing import Optional, Tuple, List, Dict
from fastapi import HTTPException
from openai import OpenAI
from langchain_openai import OpenAIEmbeddings
from config.config import settings
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

embedding_model = OpenAIEmbeddings(
    model=settings.embedding_model,
    openai_api_key=settings.openai_api_key
)

def answer_question(
    question: str,
    match_threshold: float = 0.8,
    match_count: int = 5,
    compliance_domain: Optional[str] = None
) -> Tuple[str, List[Dict[str, any]]]:
    """
    Answer a question using RAG with optional compliance domain filtering.
    
    Args:
        question: The user's question
        match_threshold: Minimum similarity threshold for document matching
        match_count: Maximum number of documents to retrieve
        compliance_domain: Optional compliance domain filter (e.g., 'GDPR', 'ISO27001')
    
    Returns:
        Tuple of (answer_string, list_of_source_documents)
    """
    q_vector = embedding_model.embed_query(question)
    
    try:
        # Call the enhanced match_documents function with domain filtering
        rpc_params = {
            "query_embedding": q_vector,
            "match_threshold": match_threshold,
            "match_count": match_count
        }
        
        # Add compliance domain filter if specified
        if compliance_domain:
            rpc_params["compliance_domain_filter"] = compliance_domain
            
        resp = supabase.rpc("match_documents", rpc_params).execute()
        
    except Exception as e:
        logger.error("Supabase RPC 'match_documents' failed", exc_info=True)
        raise HTTPException(status_code=500, detail=f"DB function error: {e}")

    rows = resp.data or []
    if not rows:
        domain_info = f" in domain '{compliance_domain}'" if compliance_domain else ""
        logger.warning(f"No documents returned by match_documents RPC{domain_info}")
        return f"I couldn't find any relevant documents{domain_info}.", []

    # Build context from retrieved documents
    context = "\n\n---\n\n".join(r["content"] for r in rows)
    
    # Prepare source documents with compliance metadata
    source_docs = []
    for r in rows:
        doc_metadata = r.get("metadata", {})
        
        # Enhance metadata with compliance information
        if compliance_domain:
            doc_metadata["queried_domain"] = compliance_domain
            
        source_doc = {
            "id": str(r["id"]),
            "similarity": float(r["similarity"]),
            "metadata": doc_metadata,
        }
        
        # Include page content if available
        if "content" in r:
            source_doc["page_content"] = r["content"][:500] + "..." if len(r["content"]) > 500 else r["content"]
            
        source_docs.append(source_doc)

    # Create compliance-aware prompt
    domain_context = ""
    if compliance_domain:
        domain_context = f"\n\nIMPORTANT: This query is in the context of {compliance_domain} compliance. Please ensure your answer addresses the specific regulatory requirements and provides accurate compliance guidance."

    prompt = (
        "Use the following context to answer the question. "
        "Provide specific references to document sections when possible. "
        "If the answer involves compliance requirements, be precise about obligations and procedures."
        f"{domain_context}\n\n"
        f"Context:\n{context}\n\n"
        f"Question: {question}\n\n"
        "Answer:"
    )

    client = OpenAI(api_key=settings.openai_api_key)
    try:
        completion = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {
                    "role": "system", 
                    "content": "You are a compliance expert assistant. Provide accurate, detailed answers based on the provided documents. Always cite specific document references when making compliance statements."
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ],
            temperature=0.1,  # Lower temperature for more consistent compliance answers
        )
    except Exception as e:
        logger.error("OpenAI ChatCompletion failed", exc_info=True)
        raise HTTPException(status_code=502, detail=f"OpenAI API error: {e}")
    
    answer = completion.choices[0].message.content.strip()
    
    # Log the successful query for analytics
    logger.info(f"Successfully answered question in domain '{compliance_domain or 'general'}' "
               f"using {len(source_docs)} documents with threshold {match_threshold}")
    
    return answer, source_docs
