from datetime import time
import logging
from typing import List, Dict, Generator, Optional, Union
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
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> Generator[Union[str, Dict], None, None]:
    start_time = time.time()
    
    # Fetch similar documents with domain filtering
    q_vec = embedding_model.embed_query(question)
    
    try:
        rpc_params = {
            "query_embedding": q_vec,
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

    docs = resp.data or []
    source_document_ids = [str(doc["id"]) for doc in docs]
    
    # Yield metadata first (will be filtered out in endpoint)
    yield {"source_document_ids": source_document_ids}
    
    # Build context from documents
    context = "\n\n---\n\n".join(d["content"] for d in docs)

    # Build conversation history
    if history:
        hist_block = "\n".join(
            f"User: {turn['question']}\nAssistant: {turn['answer']}"
            for turn in history[-5:]  # Limit to last 5 turns to manage context size
        )
    else:
        hist_block = "(no prior context)\n"

    # Create compliance-aware prompt
    domain_context = ""
    if compliance_domain:
        domain_context = f"\n\nIMPORTANT: This is a {compliance_domain} compliance query. Ensure your response addresses specific regulatory requirements and provides accurate compliance guidance."

    prompt = (
        "You are a helpful compliance assistant. Use the conversation history and document context to provide accurate, detailed answers. "
        "When discussing compliance matters, be precise about requirements and cite specific document sections when possible."
        f"{domain_context}\n\n"
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
            temperature=0.1  # Lower temperature for consistent compliance answers
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
            total_tokens_used=token_count  # Approximate token count
        )
        
        logger.info(f"Logged streaming chat history for conversation {conversation_id} "
                   f"in domain '{compliance_domain or 'general'}' with {len(source_document_ids)} sources")
                   
    except Exception as e:
        logger.error(f"Failed to log streaming chat history: {e}")

