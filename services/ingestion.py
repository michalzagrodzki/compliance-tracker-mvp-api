import os
import logging
from datetime import datetime, timezone
from fastapi import HTTPException
from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from services.vector_store import vector_store
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def ingest_pdf_sync(file_path: str) -> int:
    loader = PyPDFLoader(file_path)
    pages = loader.load()
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    chunks = splitter.split_documents(pages)
    logger.info(f"Split into {len(chunks)} chunks.")

    vector_store.add_documents(chunks)
    logger.info("Added embeddings to Supabase vector store.")

    filename = os.path.basename(file_path)
    metadata = {
        "chunks": len(chunks),
        "path": file_path,
        "ingested_at": datetime.now(timezone.utc).isoformat()
    }

    resp = supabase.table(settings.supabase_table_pdf_ingestion).insert({
        "filename": filename,
        "metadata": metadata
    }).execute()

    if hasattr(resp, "error") and resp.error:
        logger.error("Supabase 'pdf_ingestion' failed", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to record ingestion: {resp.error.message}"
        )

    logger.info(f"Finished ingestion, inserted {len(chunks)} chunks.")
    return len(chunks)
