from datetime import time
import logging
from typing import Any, List, Dict, Generator, Optional, Union
from fastapi import HTTPException
from openai import OpenAI
from config.config import settings
from db.supabase_client import create_supabase_client
from services.chat_history import insert_chat_history
from services.qa import embedding_model

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def stream_answer_sync(
    question: str,
    conversation_id: str,
    history: List[Dict[str, str]],
    audit_session_id: Optional[str] = None,
    compliance_domain: Optional[str] = None,
    match_threshold: float = 0.75,
    match_count: int = 5,
    user_id: Optional[str] = None,
    document_version: Optional[List[str]] = None,
    document_tags: Optional[List[str]] = None
) -> Generator[Union[str, Dict], None, None]:
    start_time = time.time()
    
    # Fetch similar documents with domain filtering
    q_vector = embedding_model.embed_query(question)
    
    try:
        rpc_params = {
            "query_embedding": q_vector,
            "match_threshold": match_threshold,
            "match_count": match_count
        }
        
        if compliance_domain:
            rpc_params["compliance_domain_filter"] = compliance_domain
            
        if document_version:
            rpc_params["document_version_filter"] = document_version
            
        if document_tags:
            rpc_params["document_tags_filter"] = document_tags
            
        resp = supabase.rpc("match_documents_with_domain", rpc_params).execute()
        
    except Exception as e:
        logger.error("Supabase RPC 'match_documents' failed", exc_info=True)
        raise HTTPException(status_code=500, detail=f"DB function error: {e}")

    docs = resp.data or []
    if not docs:
        domain_info = f" in domain '{compliance_domain}'" if compliance_domain else ""
        version_info = f" for version '{document_version}'" if document_version else ""
        tags_info = f" with tags {document_tags}" if document_tags else ""
        logger.warning(f"No documents returned by match_documents_with_domain RPC{domain_info}{version_info}{tags_info}")
        
        # Still log the interaction even with no results
        try:
            insert_chat_history(
                conversation_id=conversation_id,
                question=question,
                answer=f"I couldn't find any relevant documents{domain_info}{version_info}{tags_info}.",
                audit_session_id=audit_session_id,
                compliance_domain=compliance_domain,
                source_document_ids=[],
                match_threshold=match_threshold,
                match_count=match_count,
                user_id=user_id,
                response_time_ms=int((time.time() - start_time) * 1000),
                total_tokens_used=0,
                metadata={}
            )
        except Exception as e:
            logger.error(f"Failed to log no-results chat history: {e}")
            
        yield f"I couldn't find any relevant documents{domain_info}{version_info}{tags_info}."
        return
    
    source_document_ids = [str(doc["id"]) for doc in docs]
    
    aggregated_metadata = _build_aggregated_metadata(docs, compliance_domain, document_version, document_tags)
    
    # Yield metadata first (will be filtered out in endpoint)
    yield {"source_document_ids": source_document_ids, "metadata": aggregated_metadata}
    
    # Build context from documents
    context = "\n\n---\n\n".join(d["content"] for d in docs)

    # Build conversation history
    if history:
        hist_block = "\n".join(
            f"User: {turn['question']}\nAssistant: {turn['answer']}"
            for turn in history[-match_count:]  # Limit to last 5 turns to manage context size
        )
    else:
        hist_block = "(no prior context)\n"

    # Create compliance-aware prompt
    domain_context = ""
    if compliance_domain:
        domain_context = f"\n\nIMPORTANT: This query is in the context of {compliance_domain} compliance. Please ensure your answer addresses the specific regulatory requirements and provides accurate compliance guidance."

    version_context = ""
    if document_version:
        version_context = f"\n\nNOTE: This query is specifically for document version {document_version}. Ensure your answer is relevant to this version."

    tags_context = ""
    if document_tags:
        tags_context = f"\n\nCONTEXT: This query involves documents tagged with: {', '.join(document_tags)}."

    prompt = (
        "Use the following context to answer the question. "
        "Provide specific references to document sections when possible. "
        "If the answer involves compliance requirements, be precise about obligations and procedures."
        f"{domain_context}{version_context}{tags_context}\n\n"
        f"Conversation so far:\n{hist_block}\n\n"
        f"Context from documents:\n{context}\n\n"
        f"Question: {question}\nAnswer:"
    )

    # Stream response from OpenAI
    client = OpenAI(api_key=settings.openai_api_key)
    
    try:
        stream = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a compliance expert assistant. Provide accurate, detailed answers based on the provided documents and conversation history. Always cite specific document references when making compliance statements."
                },
                {
                    "role": "user", 
                    "content": prompt
                }
            ],
            stream=True,
            temperature=0.1
        )
    except Exception as e:
        logger.error("OpenAI streaming failed", exc_info=True)
        raise HTTPException(status_code=502, detail=f"OpenAI API error: {e}")

    # Stream tokens and collect full answer
    full_answer = ""
    token_count = 0
    
    for chunk in stream:
        delta = chunk.choices[0].delta.content
        if delta:
            full_answer += delta
            token_count += 1
            yield delta

    end_time = time.time()
    response_time_ms = int((end_time - start_time) * 1000)

    # Log the complete interaction to chat history
    try:
        insert_chat_history(
            conversation_id=conversation_id,
            question=question,
            answer=full_answer,
            audit_session_id=audit_session_id,
            compliance_domain=compliance_domain,
            source_document_ids=source_document_ids,
            match_threshold=match_threshold,
            match_count=match_count,
            user_id=user_id,
            response_time_ms=response_time_ms,
            total_tokens_used=token_count,
            metadata=aggregated_metadata
        )
        
        logger.info(f"Logged streaming chat history for conversation {conversation_id} "
                   f"in domain '{compliance_domain or 'general'}' with {len(source_document_ids)} sources")
                   
    except Exception as e:
        logger.error(f"Failed to log streaming chat history: {e}")

def _build_aggregated_metadata(
    docs: List[Dict[str, Any]], 
    compliance_domain: Optional[str], 
    document_version: Optional[List[str]], 
    document_tags: Optional[List[str]]
) -> Dict[str, Any]:
    """
    Build aggregated metadata from source documents, similar to qa.py approach.
    
    Args:
        docs: List of document records from the database
        compliance_domain: Queried compliance domain
        document_version: Queried document version
        document_tags: Queried document tags
        
    Returns:
        Dictionary containing aggregated metadata from all source documents
    """
    if not docs:
        return {}
    
    # Collect metadata from all documents
    source_filenames = set()
    source_domains = set()
    source_versions = set()
    all_tags = set()
    authors = set()
    titles = set()
    
    # Statistics
    total_similarity_score = 0.0
    best_match_score = 0.0
    
    document_details = []
    
    for doc in docs:
        doc_metadata = doc.get("metadata", {})
        
        # Collect unique values
        if doc.get("source_filename"):
            source_filenames.add(doc["source_filename"])
        if doc.get("compliance_domain"):
            source_domains.add(doc["compliance_domain"])
        if doc.get("document_version"):
            source_versions.add(doc["document_version"])
        if doc.get("document_tags"):
            all_tags.update(doc["document_tags"])
        if doc.get("author"):
            authors.add(doc["author"])
        if doc.get("title"):
            titles.add(doc["title"])
            
        # Calculate similarity statistics
        similarity = float(doc.get("similarity", 0))
        total_similarity_score += similarity
        best_match_score = max(best_match_score, similarity)
        
        # Collect individual document details
        document_details.append({
            "document_id": str(doc["id"]),
            "source_filename": doc.get("source_filename"),
            "compliance_domain": doc.get("compliance_domain"),
            "document_version": doc.get("document_version"),
            "document_tags": doc.get("document_tags", []),
            "similarity": similarity,
            "page_number": doc.get("page"),
            "chunk_index": doc.get("chunk_index"),
            "title": doc.get("title"),
            "author": doc.get("author")
        })
    
    # Calculate average similarity
    avg_similarity = total_similarity_score / len(docs) if docs else 0.0
    
    # Build aggregated metadata
    aggregated_metadata = {
        # Query context
        "queried_domain": compliance_domain,
        "queried_version": document_version,
        "queried_tags": document_tags,
        
        # Source document aggregations
        "source_filenames": list(source_filenames),
        "source_domains": list(source_domains),
        "source_versions": list(source_versions),
        "all_document_tags": list(all_tags),
        "source_authors": list(authors),
        "source_titles": list(titles),
        
        # Retrieval statistics
        "total_documents_retrieved": len(docs),
        "best_match_score": best_match_score,
        "average_similarity": round(avg_similarity, 4),
        "similarity_range": {
            "min": min(doc.get("similarity", 0) for doc in docs) if docs else 0,
            "max": best_match_score
        },
        
        # Individual document details
        "document_details": document_details,
        
        # Compliance metadata summary
        "compliance_summary": {
            "domains_covered": list(source_domains),
            "versions_referenced": list(source_versions),
            "regulatory_tags": [tag for tag in all_tags if any(reg in tag.lower() for reg in ['iso', 'gdpr', 'sox', 'hipaa', 'pci'])],
            "document_types": [tag for tag in all_tags if any(dtype in tag.lower() for dtype in ['policy', 'procedure', 'standard', 'guideline'])]
        }
    }
    
    return aggregated_metadata