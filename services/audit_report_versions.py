import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def list_audit_report_versions(
    audit_report_id: str,
    skip: int = 0,
    limit: int = 10
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching versions for audit report {audit_report_id}")
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_versions)
            .select("*")
            .eq("audit_report_id", audit_report_id)
            .order("version_number", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        logger.info(f"Retrieved {len(resp.data)} versions for report {audit_report_id}")
        return resp.data
        
    except Exception as e:
        logger.error(f"Failed to fetch versions for report {audit_report_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_audit_report_version_by_id(version_id: str) -> Dict[str, Any]:
    try:
        logger.info(f"Fetching audit report version with ID: {version_id}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_versions)
            .select("*")
            .eq("id", version_id)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Audit report version with ID '{version_id}' not found")
        
        logger.info(f"Found audit report version: {version_id}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch audit report version {version_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_latest_audit_report_version(audit_report_id: str) -> Dict[str, Any]:
    try:
        logger.info(f"Fetching latest version for audit report {audit_report_id}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_versions)
            .select("*")
            .eq("audit_report_id", audit_report_id)
            .order("version_number", desc=True)
            .limit(1)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"No versions found for audit report {audit_report_id}")
        
        logger.info(f"Found latest version for report {audit_report_id}: v{resp.data[0]['version_number']}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch latest version for report {audit_report_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_audit_report_version_by_number(audit_report_id: str, version_number: int) -> Dict[str, Any]:
    try:
        logger.info(f"Fetching version {version_number} for audit report {audit_report_id}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_versions)
            .select("*")
            .eq("audit_report_id", audit_report_id)
            .eq("version_number", version_number)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(
                status_code=404, 
                detail=f"Version {version_number} not found for audit report {audit_report_id}"
            )
        
        logger.info(f"Found version {version_number} for report {audit_report_id}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch version {version_number} for report {audit_report_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

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
        
        version_data = {
            "audit_report_id": audit_report_id,
            "version_number": next_version,
            "change_description": change_description,
            "changed_by": changed_by,
            "change_type": change_type,
            "report_snapshot": report_snapshot,
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

def compare_audit_report_versions(
    audit_report_id: str,
    version1: int,
    version2: int
) -> Dict[str, Any]:
    try:
        logger.info(f"Comparing versions {version1} and {version2} for report {audit_report_id}")

        version1_data = get_audit_report_version_by_number(audit_report_id, version1)
        version2_data = get_audit_report_version_by_number(audit_report_id, version2)

        snapshot1 = version1_data["report_snapshot"]
        snapshot2 = version2_data["report_snapshot"]

        changes = {}

        basic_fields = [
            "report_title", "report_status", "executive_summary",
            "total_gaps_identified", "overall_compliance_rating",
            "potential_fine_exposure", "estimated_remediation_cost"
        ]
        
        for field in basic_fields:
            val1 = snapshot1.get(field)
            val2 = snapshot2.get(field)
            if val1 != val2:
                changes[field] = {
                    f"version_{version1}": val1,
                    f"version_{version2}": val2
                }

        array_fields = ["recommendations", "action_items", "compliance_gap_ids"]
        for field in array_fields:
            arr1 = snapshot1.get(field, [])
            arr2 = snapshot2.get(field, [])
            if set(str(x) for x in arr1) != set(str(x) for x in arr2):
                changes[field] = {
                    f"version_{version1}_count": len(arr1),
                    f"version_{version2}_count": len(arr2),
                    "added": list(set(str(x) for x in arr2) - set(str(x) for x in arr1)),
                    "removed": list(set(str(x) for x in arr1) - set(str(x) for x in arr2))
                }
        
        comparison_result = {
            "audit_report_id": audit_report_id,
            "version_1": {
                "number": version1,
                "created_at": version1_data["created_at"],
                "changed_by": version1_data.get("changed_by"),
                "change_type": version1_data.get("change_type")
            },
            "version_2": {
                "number": version2,
                "created_at": version2_data["created_at"],
                "changed_by": version2_data.get("changed_by"),
                "change_type": version2_data.get("change_type")
            },
            "changes_detected": len(changes),
            "changes": changes
        }
        
        logger.info(f"Comparison complete: {len(changes)} changes detected between versions {version1} and {version2}")
        return comparison_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to compare versions for report {audit_report_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def restore_audit_report_version(
    audit_report_id: str,
    version_number: int,
    restored_by: str,
    restore_reason: str
) -> Dict[str, Any]:
    try:
        logger.info(f"Restoring report {audit_report_id} to version {version_number}")

        version_to_restore = get_audit_report_version_by_number(audit_report_id, version_number)
        snapshot = version_to_restore["report_snapshot"]

        current_report_resp = (
            supabase
            .table(settings.supabase_table_audit_reports)
            .select("*")
            .eq("id", audit_report_id)
            .execute()
        )
        
        if not current_report_resp.data:
            raise HTTPException(status_code=404, detail=f"Audit report {audit_report_id} not found")
        
        current_report = current_report_resp.data[0]

        backup_version = create_audit_report_version(
            audit_report_id=audit_report_id,
            changed_by=restored_by,
            change_description=f"Backup before restoring to version {version_number}: {restore_reason}",
            change_type="correction",
            report_snapshot=current_report
        )

        exclude_fields = {"id", "created_at", "report_generated_at"}
        update_data = {k: v for k, v in snapshot.items() if k not in exclude_fields}

        update_data.update({
            "last_modified_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })

        update_resp = (
            supabase
            .table(settings.supabase_table_audit_reports)
            .update(update_data)
            .eq("id", audit_report_id)
            .execute()
        )
        
        if hasattr(update_resp, "error") and update_resp.error:
            logger.error("Failed to restore audit report", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to restore audit report: {update_resp.error.message}"
            )

        restore_version = create_audit_report_version(
            audit_report_id=audit_report_id,
            changed_by=restored_by,
            change_description=f"Restored to version {version_number}: {restore_reason}",
            change_type="correction",
            report_snapshot=update_resp.data[0]
        )
        
        logger.info(f"Successfully restored report {audit_report_id} to version {version_number}")
        return {
            "restored_report": update_resp.data[0],
            "backup_version": backup_version,
            "restore_version": restore_version
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to restore report {audit_report_id} to version {version_number}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def delete_audit_report_version(version_id: str) -> Dict[str, Any]:
    try:
        logger.info(f"Deleting audit report version {version_id}")

        version_data = get_audit_report_version_by_id(version_id)
        audit_report_id = version_data["audit_report_id"]

        count_resp = (
            supabase
            .table(settings.supabase_table_audit_report_versions)
            .select("id", count="exact")
            .eq("audit_report_id", audit_report_id)
            .execute()
        )
        
        if count_resp.count == 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the only version of an audit report"
            )

        resp = (
            supabase
            .table(settings.supabase_table_audit_report_versions)
            .delete()
            .eq("id", version_id)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase audit report version deletion failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to delete audit report version: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Audit report version {version_id} not found")
        
        logger.info(f"Deleted audit report version {version_id}")
        return {"message": f"Audit report version {version_id} deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete audit report version {version_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_version_history_summary(audit_report_id: str) -> Dict[str, Any]:
    try:
        logger.info(f"Getting version history summary for report {audit_report_id}")

        versions = list_audit_report_versions(audit_report_id, skip=0, limit=100)
        
        if not versions:
            raise HTTPException(status_code=404, detail=f"No versions found for audit report {audit_report_id}")

        total_versions = len(versions)

        change_type_counts = {}
        contributors = set()
        
        for version in versions:
            change_type = version.get("change_type", "unknown")
            change_type_counts[change_type] = change_type_counts.get(change_type, 0) + 1
            
            changed_by = version.get("changed_by")
            if changed_by:
                contributors.add(changed_by)

        first_version = min(versions, key=lambda v: v["version_number"])
        latest_version = max(versions, key=lambda v: v["version_number"])
        
        summary = {
            "audit_report_id": audit_report_id,
            "total_versions": total_versions,
            "first_version": {
                "number": first_version["version_number"],
                "created_at": first_version["created_at"],
                "changed_by": first_version.get("changed_by")
            },
            "latest_version": {
                "number": latest_version["version_number"],
                "created_at": latest_version["created_at"],
                "changed_by": latest_version.get("changed_by"),
                "change_type": latest_version.get("change_type")
            },
            "change_type_breakdown": change_type_counts,
            "unique_contributors": len(contributors),
            "contributors": list(contributors),
            "version_timeline": [
                {
                    "version_number": v["version_number"],
                    "created_at": v["created_at"],
                    "change_type": v.get("change_type"),
                    "change_description": v.get("change_description", "")[:100] + "..." if v.get("change_description", "") and len(v.get("change_description", "")) > 100 else v.get("change_description", "")
                }
                for v in sorted(versions, key=lambda x: x["version_number"])
            ]
        }
        
        logger.info(f"Generated version history summary for report {audit_report_id}: {total_versions} versions")
        return summary
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get version history summary for report {audit_report_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")