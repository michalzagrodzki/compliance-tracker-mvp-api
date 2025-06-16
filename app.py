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
    summary="Upload a PDF document with compliance metadata",
    description="Ingests a PDF, splits into chunks, stores embeddings in Supabase with compliance domain tracking",
    tags=["Ingestion"],
)
def upload_pdf(
    file: UploadFile = File(...),
    compliance_domain: Optional[str] = Form(None, description="Compliance domain (e.g., 'GDPR', 'ISO_27001', 'SOX')"),
    document_version: Optional[str] = Form(None, description="Document version (e.g., 'v1.0', '2024-Q1')"),
    uploaded_by: Optional[str] = Form(None, description="User ID who uploaded the document")
):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported")

    if compliance_domain:
        allowed_domains = ["GDPR", "ISO_27001", "SOX", "HIPAA", "PCI_DSS", "FDA_21CFR", "ISO_9001"]
        if compliance_domain not in allowed_domains:
            logging.warning(f"Unknown compliance domain: {compliance_domain}")

    if uploaded_by:
        try:
            uuid.UUID(uploaded_by)
        except ValueError:
            raise HTTPException(status_code=400, detail="uploaded_by must be a valid UUID")
        
    try:
        contents = file.file.read()
        if not contents:
            raise HTTPException(status_code=400, detail="Empty file uploaded")
        
        os.makedirs(settings.pdf_dir, exist_ok=True)
        safe_filename = os.path.basename(file.filename)
        if not safe_filename:
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        file_path = os.path.join(settings.pdf_dir, safe_filename)
        
        counter = 1
        original_path = file_path
        while os.path.exists(file_path):
            name, ext = os.path.splitext(original_path)
            file_path = f"{name}_{counter}{ext}"
            counter += 1
        
        with open(file_path, "wb") as f:
            f.write(contents)
        
        logging.info(f"Saved file to {file_path} (size: {len(contents)} bytes)")
        
        chunk_count, ingestion_id = ingest_pdf_sync(
            file_path=file_path,
            compliance_domain=compliance_domain,
            document_version=document_version,
            uploaded_by=uploaded_by
        )
        
        return UploadResponse(
            message=f"PDF '{safe_filename}' ingested successfully",
            inserted_count=chunk_count,
            ingestion_id=ingestion_id,
            compliance_domain=compliance_domain,
            document_version=document_version
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Unexpected error during upload: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Upload failed: {str(e)}"
        )
    finally:
        # Clean up file handle
        if hasattr(file.file, 'close'):
            file.file.close()

app.include_router(router_v1)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))