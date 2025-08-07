import logging
from typing import List, Dict, Any, Optional
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings
from uuid import UUID

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def _ensure_string(value: Any) -> Optional[str]:
    """Convert UUID objects to strings, pass through None and strings as-is"""
    if value is None:
        return None
    if isinstance(value, UUID):
        return str(value)
    return str(value)

def create_audit_log(
    object_type: str,
    object_id: str,
    action: str,
    user_id: str,
    audit_session_id: Optional[str] = None,
    compliance_domain: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    risk_level: Optional[str] = None,
    tags: Optional[List[str]] = None
) -> Dict[str, Any]:
    try:
        logger.info(f"Creating audit log: {object_type}/{object_id} - {action} by {user_id}")
        
        # Ensure UUID fields are converted to strings
        audit_data = {
            "object_type": object_type,
            "object_id": _ensure_string(object_id),
            "action": action,
            "user_id": _ensure_string(user_id),
            "compliance_domain": compliance_domain,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "details": details or {},
            "risk_level": risk_level,
            "tags": tags or []
        }
        
        if audit_session_id:
            audit_data["audit_session_id"] = _ensure_string(audit_session_id)
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_log)
            .insert(audit_data)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=500, detail="Failed to create audit log entry")
        
        logger.info(f"Created audit log entry: {resp.data[0]['id']}")
        return resp.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create audit log entry", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_audit_logs(skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching audit logs: skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_log)
            .select("id, object_type, object_id, action, user_id, audit_session_id, compliance_domain, performed_at, ip_address, user_agent, details, risk_level, tags")
            .order("performed_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} audit log entries")
        return resp.data
    except Exception as e:
        logger.error("Failed to fetch audit logs", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_audit_log_by_id(log_id: str) -> Dict[str, Any]:
    try:
        logger.info(f"Fetching audit log by ID: {log_id}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_log)
            .select("id, object_type, object_id, action, user_id, audit_session_id, compliance_domain, performed_at, ip_address, user_agent, details, risk_level, tags")
            .eq("id", _ensure_string(log_id))
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Audit log with ID {log_id} not found")
        
        logger.info(f"Found audit log entry: {log_id}")
        return resp.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch audit log by ID {log_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_audit_logs_by_user(user_id: str, skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching audit logs for user: {user_id}, skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_log)
            .select("id, object_type, object_id, action, user_id, audit_session_id, compliance_domain, performed_at, ip_address, user_agent, details, risk_level, tags")
            .eq("user_id", _ensure_string(user_id))
            .order("performed_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} audit log entries for user {user_id}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch audit logs for user {user_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_audit_logs_by_object(object_type: str, object_id: str, skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching audit logs for object: {object_type}/{object_id}, skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_log)
            .select("id, object_type, object_id, action, user_id, audit_session_id, compliance_domain, performed_at, ip_address, user_agent, details, risk_level, tags")
            .eq("object_type", object_type)
            .eq("object_id", _ensure_string(object_id))
            .order("performed_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} audit log entries for {object_type}/{object_id}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch audit logs for {object_type}/{object_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_audit_logs_by_audit_session(audit_session_id: str, skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching audit logs for audit session: {audit_session_id}, skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_log)
            .select("id, object_type, object_id, action, user_id, audit_session_id, compliance_domain, performed_at, ip_address, user_agent, details, risk_level, tags")
            .eq("audit_session_id", _ensure_string(audit_session_id))
            .order("performed_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} audit log entries for audit session {audit_session_id}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch audit logs for audit session {audit_session_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_audit_logs_by_compliance_domain(compliance_domain: str, skip: int = 0, limit: int = 10) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching audit logs for compliance domain: {compliance_domain}, skip={skip}, limit={limit}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_log)
            .select("id, object_type, object_id, action, user_id, audit_session_id, compliance_domain, performed_at, ip_address, user_agent, details, risk_level, tags")
            .eq("compliance_domain", compliance_domain)
            .order("performed_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        logger.info(f"Received {len(resp.data)} audit log entries for compliance domain {compliance_domain}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch audit logs for compliance domain {compliance_domain}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_audit_logs_filtered(
    object_type: Optional[str] = None,
    object_id: Optional[str] = None,
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    audit_session_id: Optional[str] = None,
    compliance_domain: Optional[str] = None,
    risk_level: Optional[str] = None,
    skip: int = 0,
    limit: int = 10
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching filtered audit logs: object_type={object_type}, object_id={object_id}, user_id={user_id}, action={action}, audit_session_id={audit_session_id}, compliance_domain={compliance_domain}, risk_level={risk_level}, skip={skip}, limit={limit}")
        
        query = (
            supabase
            .table(settings.supabase_table_audit_log)
            .select("id, object_type, object_id, action, user_id, audit_session_id, compliance_domain, performed_at, ip_address, user_agent, details, risk_level, tags")
        )

        if object_type:
            query = query.eq("object_type", object_type)
        if object_id:
            query = query.eq("object_id", _ensure_string(object_id))
        if user_id:
            query = query.eq("user_id", _ensure_string(user_id))
        if action:
            query = query.eq("action", action)
        if audit_session_id:
            query = query.eq("audit_session_id", _ensure_string(audit_session_id))
        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
        if risk_level:
            query = query.eq("risk_level", risk_level)
        
        resp = (
            query
            .order("performed_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        logger.info(f"Received {len(resp.data)} filtered audit log entries")
        return resp.data
    except Exception as e:
        logger.error("Failed to fetch filtered audit logs", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")