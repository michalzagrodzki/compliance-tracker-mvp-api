import logging
from typing import Tuple, List, Dict
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
    match_count: int = 5
) -> Tuple[str, List[Dict[str, any]]]:
    q_vector = embedding_model.embed_query(question)
    try:
        resp = supabase.rpc(
            "match_documents",
            {
                "query_embedding": q_vector,
                "match_threshold": match_threshold,
                "match_count": match_count
            }
        ).execute()
    except Exception as e:
        logger.error("Supabase RPC 'match_documents' failed", exc_info=True)
        raise HTTPException(status_code=500,
                            detail=f"DB function error: {e}")

    rows = resp.data or []
    if not rows:
        logger.warning("No documents returned by match_documents RPC")
        return "I couldn't find any relevant documents.", []

    context = "\n\n---\n\n".join(r["content"] for r in rows)
    source_docs = [
        {
            "id":           str(r["id"]),
            "similarity":   float(r["similarity"]),
            "metadata":     r["metadata"],
        }
        for r in rows
    ]

    prompt = (
        "Use the following context to answer the question:\n\n"
        f"{context}\n\nQuestion: {question}\nAnswer:"
    )

    client = OpenAI(api_key=settings.openai_api_key)
    try:
        completion = client.chat.completions.create(
            model=settings.openai_model,
            messages=[{"role": "user", "content": prompt}],
        )
    except Exception as e:
        logger.error("OpenAI ChatCompletion failed", exc_info=True)
        raise HTTPException(status_code=502,
                            detail=f"OpenAI API error: {e}")
    answer = completion.choices[0].message.content.strip()
    return answer, source_docs
