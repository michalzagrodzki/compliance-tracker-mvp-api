import os
import hashlib
import logging
from datetime import datetime, timezone
from fastapi import HTTPException
from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from services.vector_store import vector_store
from db.supabase_client import create_supabase_client
from config.config import settings
from typing import Optional

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def calculate_file_hash(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_duplicate_file(file_hash: str) -> Optional[dict]:
    try:
        resp = supabase.table(settings.supabase_table_pdf_ingestion).select(
            "id, filename, compliance_domain, document_version"
        ).eq("file_hash", file_hash).execute()
        
        if resp.data:
            return resp.data[0]
        return None
    except Exception as e:
        logger.warning(f"Could not check for duplicates: {e}")
        return None
    
def ingest_pdf_sync(
    file_path: str,
    compliance_domain: Optional[str] = None,
    document_version: Optional[str] = None,
    uploaded_by: Optional[str] = None
) -> tuple[int, str]:
    
    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    file_hash = calculate_file_hash(file_path)

    # Check for duplicates
    existing_file = check_duplicate_file(file_hash)
    if existing_file:
        logger.warning(f"Duplicate file detected: {filename} matches existing file {existing_file['filename']}")
        raise HTTPException(
            status_code=409,
            detail=f"File already exists: {existing_file['filename']} "
                   f"(domain: {existing_file.get('compliance_domain', 'N/A')}, "
                   f"version: {existing_file.get('document_version', 'N/A')})"
        )
    
    # Create initial record with processing status
    initial_metadata = {
        "original_filename": filename,
        "file_size_bytes": file_size,
        "processing_started_at": datetime.now(timezone.utc).isoformat()
    }

    try:
        # Insert initial record
        resp = supabase.table(settings.supabase_table_pdf_ingestion).insert({
            "filename": filename,
            "compliance_domain": compliance_domain,
            "document_version": document_version,
            "uploaded_by": uploaded_by,
            "file_size": file_size,
            "file_hash": file_hash,
            "original_path": file_path,
            "processing_status": "processing",
            "metadata": initial_metadata
        }).execute()
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Failed to create initial ingestion record", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create ingestion record: {resp.error.message}"
            )
        
        ingestion_id = resp.data[0]["id"]
        logger.info(f"Created ingestion record {ingestion_id} for {filename}")
        
    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        logger.error("Database error during initial record creation", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
    try:
        # Process the PDF
        logger.info(f"Starting PDF processing for {filename}")
        loader = PyPDFLoader(file_path)
        pages = loader.load()
        
        # Add compliance metadata to each document chunk
        for page in pages:
            page.metadata.update({
                "compliance_domain": compliance_domain,
                "document_version": document_version,
                "filename": filename,
                "ingestion_id": ingestion_id,
                "file_hash": file_hash
            })
        
        splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
        chunks = splitter.split_documents(pages)
        logger.info(f"Split {filename} into {len(chunks)} chunks")
        
        # Add to vector store
        vector_store.add_documents(chunks)
        logger.info(f"Added {len(chunks)} embeddings to vector store")
        
        # Update record with success
        final_metadata = {
            **initial_metadata,
            "chunks": len(chunks),
            "pages": len(pages),
            "processing_completed_at": datetime.now(timezone.utc).isoformat(),
            "chunk_size": 1000,
            "chunk_overlap": 200
        }
        
        update_resp = supabase.table(settings.supabase_table_pdf_ingestion).update({
            "processing_status": "completed",
            "total_chunks": len(chunks),
            "metadata": final_metadata
        }).eq("id", ingestion_id).execute()
        
        if hasattr(update_resp, "error") and update_resp.error:
            logger.error("Failed to update ingestion record", exc_info=True)
            # Don't raise here as the ingestion was successful
        
        logger.info(f"Successfully ingested {filename}: {len(chunks)} chunks")
        return len(chunks), ingestion_id
        
    except Exception as e:
        logger.error(f"Error processing PDF {filename}", exc_info=True)
        
        # Update record with failure
        error_metadata = {
            **initial_metadata,
            "error_occurred_at": datetime.now(timezone.utc).isoformat(),
            "error_details": str(e)
        }
        
        try:
            supabase.table(settings.supabase_table_pdf_ingestion).update({
                "processing_status": "failed",
                "error_message": str(e),
                "metadata": error_metadata
            }).eq("id", ingestion_id).execute()
        except Exception as update_error:
            logger.error(f"Failed to update error status: {update_error}")
        
        raise HTTPException(
            status_code=500,
            detail=f"PDF processing failed: {str(e)}"
        )
