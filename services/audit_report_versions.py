import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def create_audit_report_version(
    audit_report_id: str,
    changed_by: str,
    change_description: str,
    change_type: str,
    report_snapshot: Dict[str, Any]
) -> Dict[str, Any]:
    try:
        logger.info(f"Creating new version for audit report {audit_report_id}")
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_versions)
            .select("version_number")
            .eq("audit_report_id", audit_report_id)
            .order("version_number", desc=True)
            .limit(1)
            .execute()
        )
        
        next_version = 1
        if resp.data:
            next_version = resp.data[0]["version_number"] + 1
        
        # Serialize UUIDs to strings before creating version
        serialized_snapshot = serialize_uuids(report_snapshot)
        
        version_data = {
            "audit_report_id": audit_report_id,
            "version_number": next_version,
            "change_description": change_description,
            "changed_by": changed_by,
            "change_type": change_type,
            "report_snapshot": serialized_snapshot,  # Use serialized version
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        insert_resp = (
            supabase
            .table(settings.supabase_table_audit_report_versions)
            .insert(version_data)
            .execute()
        )
        
        if hasattr(insert_resp, "error") and insert_resp.error:
            logger.error("Supabase audit report version creation failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create audit report version: {insert_resp.error.message}"
            )
        
        if not insert_resp.data:
            raise HTTPException(
                status_code=500,
                detail="Failed to create audit report version: No data returned from database"
            )
        
        logger.info(f"Created version {next_version} for audit report {audit_report_id}")
        return insert_resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create version for audit report {audit_report_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def serialize_uuids(obj: Any) -> Any:
    if isinstance(obj, uuid.UUID):
        return str(obj)
    elif isinstance(obj, dict):
        return {key: serialize_uuids(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [serialize_uuids(item) for item in obj]
    else:
        return obj