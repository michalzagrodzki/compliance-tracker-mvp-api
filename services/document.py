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
    source_filename: Optional[str] = None,
    document_tags: Optional[List[str]] = None,
    tags_match_mode: str = "any",
    approval_status: Optional[str] = None,
    uploaded_by: Optional[str] = None,
    approved_by: Optional[str] = None
) -> List[Dict[str, Any]]:
    try:
        query = supabase.table(settings.supabase_table_documents).select(
            "id, content, metadata, compliance_domain, document_version, "
            "document_tags, source_filename, source_page_number, chunk_index, "
            "approval_status, uploaded_by, approved_by, created_at, updated_at"
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
        
        if approval_status:
            query = query.eq("approval_status", approval_status)
            logger.info(f"Filtering by approval_status: {approval_status}")
        
        if uploaded_by:
            query = query.eq("uploaded_by", uploaded_by)
            logger.info(f"Filtering by uploaded_by: {uploaded_by}")
        
        if approved_by:
            query = query.eq("approved_by", approved_by)
            logger.info(f"Filtering by approved_by: {approved_by}")

        if document_tags and len(document_tags) > 0:
            if tags_match_mode == "any":

                query = query.overlaps("document_tags", document_tags)
                logger.info(f"Filtering by tags (any match): {document_tags}")
            elif tags_match_mode == "all":

                query = query.contains("document_tags", document_tags)
                logger.info(f"Filtering by tags (all match): {document_tags}")
            elif tags_match_mode == "exact":

                for tag in document_tags:
                    query = query.contains("document_tags", [tag])
                logger.info(f"Filtering by tags (exact match): {document_tags}")
        
        resp = query.order("created_at", desc=True).limit(limit).offset(skip).execute()
        
        logger.info(f"Fetched {len(resp.data)} documents with filters: "
                   f"domain={compliance_domain}, version={document_version}, "
                   f"filename={source_filename}, tags={document_tags}, "
                   f"tags_mode={tags_match_mode}, skip={skip}, limit={limit}")
        
        return resp.data
        
    except Exception as e:
        logger.error("Failed to fetch documents", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_documents_by_tags(
    tags: List[str], 
    match_mode: str = "any",
    compliance_domain: Optional[str] = None,
    skip: int = 0, 
    limit: int = 50
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching documents by tags: {tags} (mode: {match_mode})")
        
        query = supabase.table(settings.supabase_table_documents).select(
            "id, content, metadata, compliance_domain, document_version, "
            "document_tags, source_filename, source_page_number, approval_status, "
            "uploaded_by, approved_by, created_at"
        )
        
        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)

        if match_mode == "any":
            query = query.overlaps("document_tags", tags)
        elif match_mode == "all":
            query = query.contains("document_tags", tags)
        elif match_mode == "exact":
            for tag in tags:
                query = query.contains("document_tags", [tag])
        else:
            raise HTTPException(status_code=400, detail="Invalid match_mode. Use 'any', 'all', or 'exact'")
        
        resp = query.order("created_at", desc=True).limit(limit).offset(skip).execute()
        
        logger.info(f"Found {len(resp.data)} documents matching tags {tags} with mode {match_mode}")
        return resp.data
        
    except Exception as e:
        logger.error(f"Failed to fetch documents by tags: {tags}", exc_info=True)
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

def get_available_tags(
    compliance_domain: Optional[str] = None,
    tag_prefix: Optional[str] = None
) -> Dict[str, Any]:
    try:
        query = supabase.table(settings.supabase_table_documents).select("document_tags")
        
        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
        
        resp = query.execute()

        all_tags = set()
        for doc in resp.data:
            if doc.get("document_tags"):
                all_tags.update(doc["document_tags"])

        if tag_prefix:
            all_tags = {tag for tag in all_tags if tag.startswith(tag_prefix)}

        tag_categories = {
            "document_type": [tag for tag in all_tags if tag.endswith("_document")],
            "source_type": [tag for tag in all_tags if tag in ["iso_standard", "regulatory_framework", "sop", "procedure", "internal_policy", "guideline", "checklist"]],
            "status": [tag for tag in all_tags if tag in ["current", "draft", "archived", "superseded"]],
            "scope": [tag for tag in all_tags if tag in ["organizational", "departmental", "process_specific", "role_specific"]],
            "format": [tag for tag in all_tags if tag in ["policy_document", "technical_specification", "process_flow", "control_framework", "risk_matrix"]],
            "other": [tag for tag in all_tags if not any(tag in category for category in [
                ["reference_document", "implementation_document", "assessment_document", "training_document", "template_document"],
                ["iso_standard", "regulatory_framework", "sop", "procedure", "internal_policy", "guideline", "checklist"],
                ["current", "draft", "archived", "superseded"],
                ["organizational", "departmental", "process_specific", "role_specific"],
                ["policy_document", "technical_specification", "process_flow", "control_framework", "risk_matrix"]
            ])]
        }
        
        return {
            "all_tags": sorted(list(all_tags)),
            "tag_categories": {k: sorted(v) for k, v in tag_categories.items() if v},
            "total_unique_tags": len(all_tags),
            "compliance_domain": compliance_domain
        }
        
    except Exception as e:
        logger.error("Failed to fetch available tags", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")