import logging
from typing import Optional, Tuple, List, Dict
from fastapi import HTTPException
from openai import OpenAI
from langchain_openai import OpenAIEmbeddings
from config.config import settings
from db.supabase_client import create_supabase_client

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

embedding_model = OpenAIEmbeddings(
    model=settings.embedding_model,
    openai_api_key=settings.openai_api_key
)

def answer_question(
    question: str,
    match_threshold: float = 0.75,
    match_count: int = 5,
    compliance_domain: Optional[str] = None,
    document_version: Optional[List[str]] = None,
    document_tags: Optional[List[str]] = None
) -> Tuple[str, List[Dict[str, any]]]:
    """
    Answer a question using RAG with compliance-first filtering using your original function.
    
    Args:
        question: The user's question
        match_threshold: Minimum similarity threshold for document matching (default 0.75)
        match_count: Maximum number of documents to retrieve (default 5)
        compliance_domain: Optional compliance domain filter (e.g., 'GDPR', 'ISO27001')
        document_version: Optional document version filter (takes first version if list provided)
        document_tags: Optional list of tags to filter by (uses array overlap)
    
    Returns:
        Tuple of (answer_string, list_of_source_documents)
    """
    q_vector = embedding_model.embed_query(question)
    
    try:
        # Prepare parameters for your original function
        rpc_params = {
            "query_embedding": q_vector,
            "match_threshold": match_threshold,
            "match_count": match_count,
            "compliance_domain_filter": compliance_domain,
            "user_domains": None,  # You can implement user domain access control here
            "document_version_filter": document_version[0] if document_version else None,  # Take first version
            "document_tags_filter": document_tags
        }
        
        resp = supabase.rpc("match_documents_with_domain", rpc_params).execute()
        
    except Exception as e:
        logger.error("Supabase RPC 'match_documents_with_domain' failed", exc_info=True)
        raise HTTPException(status_code=500, detail=f"DB function error: {e}")

    docs = resp.data or []
    if not docs:
        domain_info = f" in domain '{compliance_domain}'" if compliance_domain else ""
        version_info = f" for version '{document_version[0]}'" if document_version else ""
        tags_info = f" with tags {document_tags}" if document_tags else ""
        logger.warning(f"No documents returned by match_documents_with_domain RPC{domain_info}{version_info}{tags_info}")
        return f"I couldn't find any relevant documents{domain_info}{version_info}{tags_info}.", []

    # Build context from retrieved documents
    context = "\n\n---\n\n".join(r["content"] for r in docs)
    
    # Prepare source documents with compliance metadata
    source_docs = []
    for r in docs:
        # Your function returns compliance fields directly + metadata jsonb
        doc_metadata = dict(r.get("metadata", {}))  # Start with existing metadata from jsonb field
        
        # Add the compliance fields returned directly by your function
        doc_metadata.update({
            "queried_domain": compliance_domain,
            "compliance_domain": r.get("compliance_domain"),  # Direct field from your function
            "document_version": r.get("document_version"),    # Direct field from your function
            "document_tags": r.get("document_tags", []),      # Direct field from your function
            "source_filename": r.get("source_filename"),      # Direct field from your function
            "source_page_number": r.get("source_page_number"), # Direct field from your function
            "chunk_index": r.get("chunk_index"),              # Direct field from your function
        })
        
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

    version_context = ""
    if document_version:
        version_context = f"\n\nNOTE: This query is specifically for document version {document_version[0]}. Ensure your answer is relevant to this version."

    tags_context = ""
    if document_tags:
        tags_context = f"\n\nCONTEXT: This query involves documents tagged with: {', '.join(document_tags)}."

    prompt = (
        "Use the following context to answer the question. "
        "Provide specific references to document sections when possible. "
        "If the answer involves compliance requirements, be precise about obligations and procedures."
        f"{domain_context}{version_context}{tags_context}\n\n"
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
            temperature=0.1,
        )
    except Exception as e:
        logger.error("OpenAI ChatCompletion failed", exc_info=True)
        raise HTTPException(status_code=502, detail=f"OpenAI API error: {e}")
    
    answer = completion.choices[0].message.content.strip()
    
    # Log the successful query for analytics
    logger.info(f"Successfully answered question in domain '{compliance_domain or 'general'}' "
               f"using {len(source_docs)} documents with threshold {match_threshold}")
    
    return answer, source_docs