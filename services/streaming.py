import logging
from typing import List, Dict, Generator
from fastapi import HTTPException
from openai import OpenAI
from config.config import settings
from db.supabase_client import create_supabase_client
from services.qa import embedding_model

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def stream_answer_sync(
    question: str,
    conversation_id: str,
    history: List[Dict[str, str]],
    match_threshold:    float = 0.75,
    match_count:        int = 5,
) -> Generator[str, None, None]:
    # fetch similar docs
    q_vec = embedding_model.embed_query(question)
    try:
        resp = supabase.rpc(
            "match_documents",
            {
                "query_embedding": q_vec,
                "match_threshold": match_threshold,
                "match_count": match_count
            }
        ).execute()
    except Exception as e:
        logger.error("Supabase RPC 'match_documents' failed", exc_info=True)
        raise HTTPException(status_code=500,
                            detail=f"DB function error: {e}")

    docs = resp.data or []
    context = "\n\n---\n\n".join(d["content"] for d in docs)

    if history:
        hist_block = "\n".join(
            f"User: {turn['question']}\nAssistant: {turn['answer']}"
            for turn in history
        )
    else:
        hist_block = "(no prior context)\n"

    prompt = (
        "You are a helpful assistant.\n\n"
        f"Conversation so far:\n{hist_block}\n\n"
        f"Context from documents:\n{context}\n\n"
        f"Question: {question}\nAnswer:"
    )

    client = OpenAI(api_key=settings.openai_api_key)
    stream = client.chat.completions.create(
        model=settings.openai_model,
        messages=[{"role": "user", "content": prompt}],
        stream=True
    )

    full_answer = ""
    for chunk in stream:
        delta = chunk.choices[0].delta.content
        if delta:
            full_answer += delta
            yield delta

    # append history
    try:
        supabase.table(settings.supabase_table_chat_history).insert({
            "conversation_id": conversation_id,
            "question": question,
            "answer": full_answer
        }).execute()
    except Exception as e:
        logging.error(f"Failed to append chat history: {e}")
