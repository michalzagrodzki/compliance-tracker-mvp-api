import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def list_audit_sessions(skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching all audit sessions: skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_sessions)
            .select("*")
            .order("started_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} audit sessions")
        return resp.data
    except Exception as e:
        logger.error("Failed to fetch audit sessions", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_audit_sessions_by_user(
    user_id: str, 
    skip: int = 0, 
    limit: int = 10
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching audit sessions for user {user_id}: skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_sessions)
            .select("*")
            .eq("user_id", user_id)
            .order("started_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} audit sessions for user {user_id}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch audit sessions for user {user_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_audit_session_by_id(session_id: str) -> Dict[str, Any]:
    try:
        logger.info(f"Fetching audit session with ID: {session_id}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_sessions)
            .select("*")
            .eq("id", session_id)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Audit session {session_id} not found")
        
        logger.info(f"Found audit session {session_id}")
        return resp.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch audit session {session_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_audit_sessions_by_active_status(
    is_active: bool, 
    skip: int = 0, 
    limit: int = 10
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching audit sessions with is_active={is_active}: skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_sessions)
            .select("*")
            .eq("is_active", is_active)
            .order("started_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} audit sessions with is_active={is_active}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch audit sessions by active status", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_audit_sessions_by_domain(
    compliance_domain: str, 
    skip: int = 0, 
    limit: int = 10
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching audit sessions for domain {compliance_domain}: skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_sessions)
            .select("*")
            .eq("compliance_domain", compliance_domain)
            .order("started_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} audit sessions for domain {compliance_domain}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch audit sessions for domain {compliance_domain}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def search_audit_sessions(
    compliance_domain: Optional[str] = None,
    user_id: Optional[str] = None,
    started_at: Optional[datetime] = None,
    ended_at: Optional[datetime] = None,
    is_active: Optional[bool] = None,
    skip: int = 0,
    limit: int = 10
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Searching audit sessions with filters: domain={compliance_domain}, "
                   f"user_id={user_id}, started_at={started_at}, ended_at={ended_at}, "
                   f"is_active={is_active}, skip={skip}, limit={limit}")
        
        query = supabase.table(settings.supabase_table_audit_sessions).select("*")
        
        # Apply filters conditionally
        if compliance_domain is not None:
            query = query.eq("compliance_domain", compliance_domain)
        
        if user_id is not None:
            query = query.eq("user_id", user_id)
        
        if is_active is not None:
            query = query.eq("is_active", is_active)
        
        if started_at is not None:
            query = query.gte("started_at", started_at.isoformat())
        
        if ended_at is not None:
            query = query.lte("ended_at", ended_at.isoformat())
        
        resp = (
            query
            .order("started_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        logger.info(f"Search returned {len(resp.data)} audit sessions")
        return resp.data
    except Exception as e:
        logger.error("Failed to search audit sessions", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def create_audit_session(
    user_id: str,
    session_name: str,
    compliance_domain: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> Dict[str, Any]:
    try:
        logger.info(f"Creating new audit session for user {user_id} in domain {compliance_domain}")
        
        session_data = {
            "user_id": user_id,
            "session_name": session_name,
            "compliance_domain": compliance_domain,
            "is_active": True,
            "total_queries": 0
        }
        
        if ip_address:
            session_data["ip_address"] = ip_address
        
        if user_agent:
            session_data["user_agent"] = user_agent
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_sessions)
            .insert(session_data)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase audit session creation failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create audit session: {resp.error.message}"
            )
        
        logger.info(f"Created audit session with ID: {resp.data[0]['id']}")
        return resp.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create audit session", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def update_audit_session(
    session_id: str,
    ended_at: Optional[datetime] = None,
    session_summary: Optional[str] = None,
    is_active: Optional[bool] = None,
    total_queries: Optional[int] = None
) -> Dict[str, Any]:
    try:
        logger.info(f"Updating audit session {session_id}")
        
        update_data = {}
        
        if ended_at is not None:
            update_data["ended_at"] = ended_at.isoformat()
        
        if session_summary is not None:
            update_data["session_summary"] = session_summary
        
        if is_active is not None:
            update_data["is_active"] = is_active
        
        if total_queries is not None:
            update_data["total_queries"] = total_queries
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No update data provided")
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_sessions)
            .update(update_data)
            .eq("id", session_id)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase audit session update failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to update audit session: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Audit session {session_id} not found")
        
        logger.info(f"Updated audit session {session_id}")
        return resp.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update audit session {session_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def delete_audit_session(session_id: str, soft_delete: bool = True) -> Dict[str, Any]:
    try:
        logger.info(f"Deleting audit session {session_id} (soft_delete={soft_delete})")
        
        if soft_delete:
            # Soft delete: just set is_active to False and add end timestamp
            update_data = {
                "is_active": False,
                "ended_at": datetime.now(timezone.utc).isoformat()
            }
            
            resp = (
                supabase
                .table(settings.supabase_table_audit_sessions)
                .update(update_data)
                .eq("id", session_id)
                .execute()
            )
            
            if hasattr(resp, "error") and resp.error:
                logger.error("Supabase audit session soft delete failed", exc_info=True)
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to soft delete audit session: {resp.error.message}"
                )
            
            if not resp.data:
                raise HTTPException(status_code=404, detail=f"Audit session {session_id} not found")
            
            logger.info(f"Soft deleted audit session {session_id}")
            return resp.data[0]
        else:
            # Hard delete: actually remove the record
            resp = (
                supabase
                .table(settings.supabase_table_audit_sessions)
                .delete()
                .eq("id", session_id)
                .execute()
            )
            
            if hasattr(resp, "error") and resp.error:
                logger.error("Supabase audit session hard delete failed", exc_info=True)
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to hard delete audit session: {resp.error.message}"
                )
            
            if not resp.data:
                raise HTTPException(status_code=404, detail=f"Audit session {session_id} not found")
            
            logger.info(f"Hard deleted audit session {session_id}")
            return {"message": f"Audit session {session_id} permanently deleted"}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete audit session {session_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_audit_session_statistics(
    compliance_domain: Optional[str] = None,
    user_id: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
) -> Dict[str, Any]:
    try:
        logger.info(f"Getting audit session statistics with filters")
        
        # Build query
        query = supabase.table(settings.supabase_table_audit_sessions).select("*")
        
        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
        
        if user_id:
            query = query.eq("user_id", user_id)
        
        if start_date:
            query = query.gte("started_at", start_date.isoformat())
        
        if end_date:
            query = query.lte("started_at", end_date.isoformat())
        
        resp = query.execute()
        
        sessions = resp.data
        
        # Calculate statistics
        total_sessions = len(sessions)
        active_sessions = len([s for s in sessions if s.get("is_active", False)])
        completed_sessions = total_sessions - active_sessions
        
        total_queries = sum(s.get("total_queries", 0) for s in sessions)
        avg_queries_per_session = total_queries / total_sessions if total_sessions > 0 else 0
        
        # Domain breakdown
        domain_counts = {}
        for session in sessions:
            domain = session.get("compliance_domain", "Unknown")
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        
        # User breakdown
        user_counts = {}
        for session in sessions:
            user = session.get("user_id", "Unknown")
            user_counts[user] = user_counts.get(user, 0) + 1
        
        stats = {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "completed_sessions": completed_sessions,
            "total_queries": total_queries,
            "avg_queries_per_session": round(avg_queries_per_session, 2),
            "sessions_by_domain": domain_counts,
            "sessions_by_user": user_counts,
            "filters_applied": {
                "compliance_domain": compliance_domain,
                "user_id": user_id,
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None
            }
        }
        
        logger.info(f"Generated statistics for {total_sessions} audit sessions")
        return stats
        
    except Exception as e:
        logger.error("Failed to get audit session statistics", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def add_pdf_ingestion_to_session(
    session_id: str,
    pdf_ingestion_id: str,
    added_by: str,
    notes: Optional[str] = None
) -> Dict[str, Any]:
    try:
        logger.info(f"Adding PDF ingestion {pdf_ingestion_id} to audit session {session_id}")

        existing_resp = (
            supabase
            .table(settings.supabase_table_audit_session_pdf_ingestions)
            .select("*")
            .eq("audit_session_id", session_id)
            .eq("pdf_ingestion_id", pdf_ingestion_id)
            .execute()
        )
        
        if existing_resp.data:
            raise HTTPException(
                status_code=409,
                detail="PDF ingestion is already associated with this audit session"
            )

        session_resp = (
            supabase
            .table(settings.supabase_table_audit_sessions)
            .select("id")
            .eq("id", session_id)
            .execute()
        )
        
        if not session_resp.data:
            raise HTTPException(status_code=404, detail="Audit session not found")

        pdf_resp = (
            supabase
            .table(settings.supabase_table_pdf_ingestion)
            .select("id")
            .eq("id", pdf_ingestion_id)
            .execute()
        )
        
        if not pdf_resp.data:
            raise HTTPException(status_code=404, detail="PDF ingestion not found")

        relationship_data = {
            "audit_session_id": session_id,
            "pdf_ingestion_id": pdf_ingestion_id,
            "added_by": added_by,
            "added_at": datetime.now(timezone.utc).isoformat()
        }
        
        if notes:
            relationship_data["notes"] = notes
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_session_pdf_ingestions)
            .insert(relationship_data)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Failed to add PDF ingestion to audit session", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to add PDF ingestion to session: {resp.error.message}"
            )
        
        logger.info(f"Successfully added PDF ingestion {pdf_ingestion_id} to audit session {session_id}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to add PDF ingestion to audit session", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def remove_pdf_ingestion_from_session(
    session_id: str,
    pdf_ingestion_id: str
) -> Dict[str, Any]:
    try:
        logger.info(f"Removing PDF ingestion {pdf_ingestion_id} from audit session {session_id}")

        existing_resp = (
            supabase
            .table(settings.supabase_table_audit_session_pdf_ingestions)
            .select("*")
            .eq("audit_session_id", session_id)
            .eq("pdf_ingestion_id", pdf_ingestion_id)
            .execute()
        )
        
        if not existing_resp.data:
            raise HTTPException(
                status_code=404,
                detail="PDF ingestion is not associated with this audit session"
            )

        resp = (
            supabase
            .table(settings.supabase_table_audit_session_pdf_ingestions)
            .delete()
            .eq("audit_session_id", session_id)
            .eq("pdf_ingestion_id", pdf_ingestion_id)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Failed to remove PDF ingestion from audit session", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to remove PDF ingestion from session: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(
                status_code=404,
                detail="Relationship not found or already removed"
            )
        
        logger.info(f"Successfully removed PDF ingestion {pdf_ingestion_id} from audit session {session_id}")
        return {"message": f"PDF ingestion removed from audit session", "removed_relationship": resp.data[0]}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to remove PDF ingestion from audit session", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_pdf_ingestions_for_session(
    session_id: str,
    skip: int = 0,
    limit: int = 10
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Getting PDF ingestions for audit session {session_id}")

        resp = (
            supabase
            .table(settings.supabase_table_audit_session_pdf_ingestions)
            .select("""
                *,
                pdf_ingestion:pdf_ingestion_id (
                    id,
                    filename,
                    compliance_domain,
                    document_version,
                    uploaded_by,
                    file_size,
                    processing_status,
                    total_chunks,
                    ingested_at,
                    metadata
                )
            """)
            .eq("audit_session_id", session_id)
            .order("added_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Failed to get PDF ingestions for audit session", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to get PDF ingestions: {resp.error.message}"
            )
        
        result = []
        for item in resp.data:
            pdf_data = item.get("pdf_ingestion", {})
            if pdf_data:
                pdf_data.update({
                    "relationship_id": item["id"],
                    "added_at": item["added_at"],
                    "added_by": item["added_by"],
                    "notes": item.get("notes")
                })
                result.append(pdf_data)
        
        logger.info(f"Retrieved {len(result)} PDF ingestions for audit session {session_id}")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get PDF ingestions for audit session", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def bulk_add_pdf_ingestions_to_session(
    session_id: str,
    pdf_ingestion_ids: List[str],
    added_by: str,
    notes: Optional[str] = None
) -> Dict[str, Any]:
    """Add multiple PDF ingestions to an audit session"""
    try:
        logger.info(f"Bulk adding {len(pdf_ingestion_ids)} PDF ingestions to audit session {session_id}")
        
        # Verify the audit session exists
        session_resp = (
            supabase
            .table(settings.supabase_table_audit_sessions)
            .select("id")
            .eq("id", session_id)
            .execute()
        )
        
        if not session_resp.data:
            raise HTTPException(status_code=404, detail="Audit session not found")
        
        # Check for existing relationships
        existing_resp = (
            supabase
            .table(settings.supabase_table_audit_session_pdf_ingestions)
            .select("pdf_ingestion_id")
            .eq("audit_session_id", session_id)
            .in_("pdf_ingestion_id", pdf_ingestion_ids)
            .execute()
        )
        
        existing_ids = {item["pdf_ingestion_id"] for item in existing_resp.data}
        new_pdf_ids = [pid for pid in pdf_ingestion_ids if pid not in existing_ids]
        
        if not new_pdf_ids:
            raise HTTPException(
                status_code=409,
                detail="All PDF ingestions are already associated with this audit session"
            )
        
        # Verify all PDF ingestions exist
        pdf_resp = (
            supabase
            .table(settings.supabase_table_pdf_ingestion)
            .select("id")
            .in_("id", new_pdf_ids)
            .execute()
        )
        
        found_pdf_ids = {item["id"] for item in pdf_resp.data}
        invalid_ids = [pid for pid in new_pdf_ids if pid not in found_pdf_ids]
        
        if invalid_ids:
            raise HTTPException(
                status_code=404,
                detail=f"PDF ingestions not found: {', '.join(invalid_ids)}"
            )
        
        # Create relationships
        relationships = []
        for pdf_id in new_pdf_ids:
            relationship_data = {
                "audit_session_id": session_id,
                "pdf_ingestion_id": pdf_id,
                "added_by": added_by,
                "added_at": datetime.now(timezone.utc).isoformat()
            }
            
            if notes:
                relationship_data["notes"] = notes
            
            relationships.append(relationship_data)
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_session_pdf_ingestions)
            .insert(relationships)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Failed to bulk add PDF ingestions to audit session", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to add PDF ingestions to session: {resp.error.message}"
            )
        
        logger.info(f"Successfully bulk added {len(new_pdf_ids)} PDF ingestions to audit session {session_id}")
        
        result = {
            "added_relationships": resp.data,
            "added_count": len(new_pdf_ids),
            "skipped_existing": list(existing_ids),
            "skipped_count": len(existing_ids)
        }
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to bulk add PDF ingestions to audit session", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def bulk_remove_pdf_ingestions_from_session(
    session_id: str,
    pdf_ingestion_ids: List[str]
) -> Dict[str, Any]:
    """Remove multiple PDF ingestions from an audit session"""
    try:
        logger.info(f"Bulk removing {len(pdf_ingestion_ids)} PDF ingestions from audit session {session_id}")
        
        # Check which relationships exist
        existing_resp = (
            supabase
            .table(settings.supabase_table_audit_session_pdf_ingestions)
            .select("*")
            .eq("audit_session_id", session_id)
            .in_("pdf_ingestion_id", pdf_ingestion_ids)
            .execute()
        )
        
        if not existing_resp.data:
            raise HTTPException(
                status_code=404,
                detail="No PDF ingestions are associated with this audit session"
            )
        
        existing_pdf_ids = [item["pdf_ingestion_id"] for item in existing_resp.data]
        
        # Remove the relationships
        resp = (
            supabase
            .table(settings.supabase_table_audit_session_pdf_ingestions)
            .delete()
            .eq("audit_session_id", session_id)
            .in_("pdf_ingestion_id", existing_pdf_ids)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Failed to bulk remove PDF ingestions from audit session", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to remove PDF ingestions from session: {resp.error.message}"
            )
        
        removed_count = len(resp.data)
        not_found_ids = [pid for pid in pdf_ingestion_ids if pid not in existing_pdf_ids]
        
        logger.info(f"Successfully bulk removed {removed_count} PDF ingestions from audit session {session_id}")
        
        result = {
            "message": f"Removed {removed_count} PDF ingestions from audit session",
            "removed_relationships": resp.data,
            "removed_count": removed_count,
            "not_found_ids": not_found_ids,
            "not_found_count": len(not_found_ids)
        }
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to bulk remove PDF ingestions from audit session", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")