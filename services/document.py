import logging
from typing import List, Dict, Any, Optional
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def list_documents(
    skip: int = 0, 
    limit: int = 10,
    compliance_domain: Optional[str] = None,
    document_version: Optional[str] = None,
    source_filename: Optional[str] = None
) -> List[Dict[str, Any]]:
    try:
        query = supabase.table(settings.supabase_table_documents).select(
            "id, content, metadata, compliance_domain, document_version, "
            "document_tags, source_filename, source_page_number, chunk_index, "
            "approval_status, created_at, updated_at"
        )
        
        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
            logger.info(f"Filtering by compliance_domain: {compliance_domain}")
        
        if document_version:
            query = query.eq("document_version", document_version)
            logger.info(f"Filtering by document_version: {document_version}")
        
        if source_filename:
            query = query.ilike("source_filename", f"%{source_filename}%")
            logger.info(f"Filtering by source_filename (partial): {source_filename}")
        
        resp = query.limit(limit).offset(skip).execute()
        
        logger.info(f"Fetched {len(resp.data)} documents with filters: "
                   f"domain={compliance_domain}, version={document_version}, "
                   f"filename={source_filename}, skip={skip}, limit={limit}")
        
        return resp.data
        
    except Exception as e:
        logger.error("Failed to fetch documents", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


def get_documents_by_source_filename(source_filename: str) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching all chunks for source_filename: {source_filename}")
        resp = (
            supabase
            .table(settings.supabase_table_documents)
            .select("id, content, metadata, compliance_domain, document_version, "
                   "source_filename, source_page_number, chunk_index, approval_status")
            .eq("source_filename", source_filename)
            .order("chunk_index", desc=False)
            .execute()
        )
        
        logger.info(f"Found {len(resp.data)} chunks for {source_filename}")
        return resp.data
        
    except Exception as e:
        logger.error(f"Failed to fetch documents for source_filename: {source_filename}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


def get_documents_by_compliance_domain(
    compliance_domain: str, 
    skip: int = 0, 
    limit: int = 50
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching documents for compliance_domain: {compliance_domain}")
        resp = (
            supabase
            .table(settings.supabase_table_documents)
            .select("id, content, metadata, compliance_domain, document_version, "
                   "source_filename, source_page_number, approval_status, created_at")
            .eq("compliance_domain", compliance_domain)
            .order("created_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        logger.info(f"Found {len(resp.data)} documents for domain {compliance_domain}")
        return resp.data
        
    except Exception as e:
        logger.error(f"Failed to fetch documents for compliance_domain: {compliance_domain}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


def get_documents_by_version(
    document_version: str, 
    skip: int = 0, 
    limit: int = 50
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching documents for version: {document_version}")
        resp = (
            supabase
            .table(settings.supabase_table_documents)
            .select("id, content, metadata, compliance_domain, document_version, "
                   "source_filename, approval_status, created_at")
            .eq("document_version", document_version)
            .order("compliance_domain", desc=False)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        logger.info(f"Found {len(resp.data)} documents for version {document_version}")
        return resp.data
        
    except Exception as e:
        logger.error(f"Failed to fetch documents for version: {document_version}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")


def get_documents_by_domain_and_version(
    compliance_domain: str,
    document_version: str, 
    skip: int = 0, 
    limit: int = 50
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching documents for domain: {compliance_domain}, version: {document_version}")
        resp = (
            supabase
            .table(settings.supabase_table_documents)
            .select("id, content, metadata, compliance_domain, document_version, "
                   "source_filename, source_page_number, approval_status, created_at")
            .eq("compliance_domain", compliance_domain)
            .eq("document_version", document_version)
            .order("source_filename", desc=False)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        logger.info(f"Found {len(resp.data)} documents for domain {compliance_domain}, version {document_version}")
        return resp.data
        
    except Exception as e:
        logger.error(f"Failed to fetch documents for domain: {compliance_domain}, version: {document_version}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")