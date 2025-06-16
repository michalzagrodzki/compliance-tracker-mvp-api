import os
from typing import Any
import uuid
from fastapi import FastAPI, HTTPException, APIRouter, File, UploadFile
from services.chat_history import get_chat_history
from services.db_check import check_database_connection
from services.document import list_documents
from services.history import get_history
from services.ingestion import ingest_pdf_sync
from services.qa import answer_question
from services.schemas import QueryRequest, QueryResponse, ChatHistoryItem, UploadResponse
from typing import Any, List, Dict
import logging
from fastapi import Query
from config.config import settings, tags_metadata
from fastapi.responses import StreamingResponse
from services.streaming import stream_answer_sync
from config.cors import configure_cors

logging.basicConfig(
    level=logging.DEBUG,  # or DEBUG
    format="%(asctime)s - %(levelname)s - %(message)s"
)

app = FastAPI(
    title="RAG FastAPI Supabase API",
    version="1.0.0",
    description="RAG service using Supabase vector store and OpenAI API",
    openapi_tags=tags_metadata,
)

configure_cors(app)

router_v1 = APIRouter(prefix="/v1")

@router_v1.get("/test-db",
               tags=["Health"])
def test_db():
    data = check_database_connection()
    return {"status": "ok", "result": data}

@router_v1.get("/documents",
    summary="List documents with pagination",
    description="Fetches paginated rows from the Supabase 'documents' table.",
    response_model=List[Dict[str, Any]],
    tags=["Documents"],
)
def get_all_documents(skip: int = Query(0, ge=0), limit: int = Query(10, ge=1, le=100)) -> Any:
    return list_documents(skip=skip, limit=limit)

@router_v1.post("/query",
    response_model=QueryResponse,
    summary="Query the knowledge base",
    description="Retrieval-Augmented Generation over ingested documents.",
    tags=["RAG"],
)
def query_qa(req: QueryRequest) -> QueryResponse:
    answer, sources = answer_question(req.question, match_threshold=0.75, match_count=5)
    return QueryResponse(answer=answer, source_docs=sources)

@router_v1.get("/history/{conversation_id}",
    response_model=List[ChatHistoryItem],
    summary="Get chat history for a conversation",
    description="Returns an array of { question, answer } for the given conversation_id",
    tags=["History"],
)
def read_history(conversation_id: str):
    return get_chat_history(conversation_id)

@router_v1.post("/query-stream",
    response_model=None,
    summary="Streamed Q&A with history",
    tags=["RAG"],
)
def query_stream(req: QueryRequest):
    # 0) ensure we have a UUID to track this conversation
    if req.conversation_id:
        try:
            uuid.UUID(req.conversation_id)
            conversation_id = req.conversation_id
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid conversation_id format (must be UUID)")
    else:
        conversation_id = str(uuid.uuid4())

    # 1) load history
    history = get_history(conversation_id)

    # 2) stream tokens, then append history at the end
    def event_generator():
        for token in stream_answer_sync(req.question, conversation_id, history):
            yield token

    return StreamingResponse(
        event_generator(),
        media_type="text/plain; charset=utf-8",
        headers={"x-conversation-id": conversation_id}
    )

@router_v1.post("/upload",
    response_model=UploadResponse,
    summary="Upload a PDF document",
    description="Ingests a PDF, splits into chunks, and stores embeddings in Supabase",
    tags=["Ingestion"],
)
def upload_pdf(file: UploadFile = File(...)):
    # validate file type
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported")

    # read & save locally
    contents = file.file.read()   # sync read
    os.makedirs(settings.pdf_dir, exist_ok=True)
    path = os.path.join(settings.pdf_dir, file.filename)
    with open(path, "wb") as f:
        f.write(contents)

    # ingest
    count = ingest_pdf_sync(path)
    
    return UploadResponse(
        message="PDF ingested successfully",
        inserted_count=count
    )

app.include_router(router_v1)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))