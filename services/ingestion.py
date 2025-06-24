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
from typing import Any, Dict, List, Optional

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
    uploaded_by: Optional[str] = None,
    document_tags: Optional[List[str]] = None
) -> tuple[int, str]:
    
    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    file_hash = calculate_file_hash(file_path)

    existing_file = check_duplicate_file(file_hash)
    if existing_file:
        logger.warning(f"Duplicate file detected: {filename} matches existing file {existing_file['filename']}")
        raise HTTPException(
            status_code=409,
            detail=f"File already exists: {existing_file['filename']} "
                   f"(domain: {existing_file.get('compliance_domain', 'N/A')}, "
                   f"version: {existing_file.get('document_version', 'N/A')})"
        )

    initial_metadata = {
        "original_filename": filename,
        "file_size_bytes": file_size,
        "processing_started_at": datetime.now(timezone.utc).isoformat(),
        "document_tags": document_tags or []
    }

    try:
        resp = supabase.table(settings.supabase_table_pdf_ingestion).insert({
            "filename": filename,
            "compliance_domain": compliance_domain,
            "document_version": document_version,
            "uploaded_by": uploaded_by,
            "file_size": file_size,
            "file_hash": file_hash,
            "original_path": file_path,
            "processing_status": "processing",
            "metadata": initial_metadata,
            "document_tags": document_tags 
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
        logger.info(f"Starting PDF processing for {filename}")
        loader = PyPDFLoader(file_path)
        pages = loader.load()

        for page in pages:
            page.metadata.update({
                "compliance_domain": compliance_domain,
                "document_version": document_version,
                "filename": filename,
                "ingestion_id": ingestion_id,
                "file_hash": file_hash,
                "document_tags": document_tags or []
            })
        
        splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
        chunks = splitter.split_documents(pages)
        logger.info(f"Split {filename} into {len(chunks)} chunks")

        vector_store.add_documents(chunks)
        logger.info(f"Added {len(chunks)} embeddings to vector store")

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

def list_pdf_ingestions(skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching PDF ingestions: skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_pdf_ingestion)
            .select("*")
            .order("ingested_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} PDF ingestions")
        return resp.data
    except Exception as e:
        logger.error("Failed to fetch PDF ingestions", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_pdf_ingestions_by_compliance_domain(
    compliance_domain: str, 
    skip: int = 0, 
    limit: int = 10
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching PDF ingestions for domain {compliance_domain}: skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_pdf_ingestion)
            .select("*")
            .eq("compliance_domain", compliance_domain)
            .order("ingested_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} PDF ingestions for domain {compliance_domain}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch PDF ingestions for domain {compliance_domain}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_pdf_ingestions_by_user(
    user_id: str, 
    skip: int = 0, 
    limit: int = 10
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching PDF ingestions for user {user_id}: skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_pdf_ingestion)
            .select("*")
            .eq("uploaded_by", user_id)
            .order("ingested_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} PDF ingestions for user {user_id}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch PDF ingestions for user {user_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_pdf_ingestions_by_version(
    document_version: str, 
    skip: int = 0, 
    limit: int = 10,
    exact_match: bool = False
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching PDF ingestions for version {document_version} (exact_match={exact_match}): skip={skip}, limit={limit}")
        
        query = supabase.table(settings.supabase_table_pdf_ingestion).select("*")
        
        if exact_match:
            query = query.eq("document_version", document_version)
        else:
            query = query.ilike("document_version", f"%{document_version}%")
        
        resp = (
            query
            .order("ingested_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        logger.info(f"Received {len(resp.data)} PDF ingestions for version {document_version}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch PDF ingestions for version {document_version}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_pdf_ingestion_by_id(ingestion_id: str) -> Dict[str, Any]:
    try:
        logger.info(f"Fetching PDF ingestion with ID: {ingestion_id}")
        resp = (
            supabase
            .table(settings.supabase_table_pdf_ingestion)
            .select("*")
            .eq("id", ingestion_id)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"PDF ingestion {ingestion_id} not found")
        
        logger.info(f"Found PDF ingestion {ingestion_id}")
        return resp.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch PDF ingestion {ingestion_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def search_pdf_ingestions(
    compliance_domain: Optional[str] = None,
    uploaded_by: Optional[str] = None,
    document_version: Optional[str] = None,
    processing_status: Optional[str] = None,
    filename_search: Optional[str] = None,
    ingested_after: Optional[datetime] = None,
    ingested_before: Optional[datetime] = None,
    document_tags: Optional[List[str]] = None,
    tags_match_mode: str = "any",
    skip: int = 0,
    limit: int = 10
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Searching PDF ingestions with filters: domain={compliance_domain}, "
                   f"user={uploaded_by}, version={document_version}, status={processing_status}, "
                   f"filename={filename_search}, after={ingested_after}, before={ingested_before}, "
                   f"tags={document_tags}, tags_match_mode={tags_match_mode}")
        
        query = supabase.table(settings.supabase_table_pdf_ingestion).select("*")
        
        if compliance_domain is not None:
            query = query.eq("compliance_domain", compliance_domain)
        
        if uploaded_by is not None:
            query = query.eq("uploaded_by", uploaded_by)
        
        if processing_status is not None:
            query = query.eq("processing_status", processing_status)
        
        if document_version is not None:
            query = query.ilike("document_version", f"%{document_version}%")
        
        if filename_search is not None:
            query = query.ilike("filename", f"%{filename_search}%")
        
        if ingested_after is not None:
            query = query.gte("ingested_at", ingested_after.isoformat())
        
        if ingested_before is not None:
            query = query.lte("ingested_at", ingested_before.isoformat())

        if document_tags:
            if tags_match_mode == "any":
                query = query.overlaps("document_tags", document_tags)
            elif tags_match_mode == "all":
                query = query.contains("document_tags", document_tags)
            elif tags_match_mode == "exact":
                query = query.eq("document_tags", document_tags)
        
        resp = (
            query
            .order("ingested_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        logger.info(f"Search returned {len(resp.data)} PDF ingestions")
        return resp.data
    except Exception as e:
        logger.error("Failed to search PDF ingestions", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def delete_pdf_ingestion(ingestion_id: str, soft_delete: bool = True) -> Dict[str, Any]:
    try:
        logger.info(f"Deleting PDF ingestion {ingestion_id} (soft_delete={soft_delete})")
        
        if soft_delete:
            update_data = {
                "processing_status": "deleted",
                "metadata": {
                    "deleted_at": datetime.now(timezone.utc).isoformat(),
                    "deletion_type": "soft_delete"
                }
            }
            
            resp = (
                supabase
                .table(settings.supabase_table_pdf_ingestion)
                .update(update_data)
                .eq("id", ingestion_id)
                .execute()
            )
            
            if hasattr(resp, "error") and resp.error:
                logger.error("Supabase PDF ingestion soft delete failed", exc_info=True)
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to soft delete PDF ingestion: {resp.error.message}"
                )
            
            if not resp.data:
                raise HTTPException(status_code=404, detail=f"PDF ingestion {ingestion_id} not found")
            
            logger.info(f"Soft deleted PDF ingestion {ingestion_id}")
            return resp.data[0]
        else:
            resp = (
                supabase
                .table(settings.supabase_table_pdf_ingestion)
                .delete()
                .eq("id", ingestion_id)
                .execute()
            )
            
            if hasattr(resp, "error") and resp.error:
                logger.error("Supabase PDF ingestion hard delete failed", exc_info=True)
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to hard delete PDF ingestion: {resp.error.message}"
                )
            
            if not resp.data:
                raise HTTPException(status_code=404, detail=f"PDF ingestion {ingestion_id} not found")
            
            logger.info(f"Hard deleted PDF ingestion {ingestion_id}")
            return {"message": f"PDF ingestion {ingestion_id} permanently deleted"}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete PDF ingestion {ingestion_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")