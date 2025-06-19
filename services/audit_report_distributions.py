import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def list_audit_report_distributions(
    audit_report_id: Optional[str] = None,
    distributed_to: Optional[str] = None,
    distribution_method: Optional[str] = None,
    is_active: Optional[bool] = None,
    skip: int = 0,
    limit: int = 10
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching audit report distributions: skip={skip}, limit={limit}")
        
        query = supabase.table(settings.supabase_table_audit_report_distributions).select("*")
        
        if audit_report_id:
            query = query.eq("audit_report_id", audit_report_id)
        if distributed_to:
            query = query.ilike("distributed_to", f"%{distributed_to}%")
        if distribution_method:
            query = query.eq("distribution_method", distribution_method)
        if is_active is not None:
            query = query.eq("is_active", is_active)
        
        resp = query.order("distributed_at", desc=True).limit(limit).offset(skip).execute()
        
        logger.info(f"Retrieved {len(resp.data)} audit report distributions")
        return resp.data
        
    except Exception as e:
        logger.error("Failed to fetch audit report distributions", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_audit_report_distribution_by_id(distribution_id: str) -> Dict[str, Any]:
    try:
        logger.info(f"Fetching audit report distribution with ID: {distribution_id}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_distributions)
            .select("*")
            .eq("id", distribution_id)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Audit report distribution with ID '{distribution_id}' not found")
        
        logger.info(f"Found audit report distribution: {distribution_id}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch audit report distribution {distribution_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_distributions_by_report_id(audit_report_id: str) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching distributions for audit report {audit_report_id}")
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_distributions)
            .select("*")
            .eq("audit_report_id", audit_report_id)
            .order("distributed_at", desc=True)
            .execute()
        )
        
        logger.info(f"Found {len(resp.data)} distributions for report {audit_report_id}")
        return resp.data
        
    except Exception as e:
        logger.error(f"Failed to fetch distributions for report {audit_report_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def create_audit_report_distribution(
    audit_report_id: str,
    distributed_to: str,
    distribution_method: str,
    distribution_format: str,
    distributed_by: str,
    external_reference: Optional[str] = None,
    expiry_date: Optional[datetime] = None
) -> Dict[str, Any]:
    try:
        logger.info(f"Creating distribution for audit report {audit_report_id} to {distributed_to}")

        report_resp = (
            supabase
            .table(settings.supabase_table_audit_reports)
            .select("id, report_status, confidentiality_level")
            .eq("id", audit_report_id)
            .execute()
        )
        
        if not report_resp.data:
            raise HTTPException(status_code=404, detail=f"Audit report {audit_report_id} not found")
        
        report = report_resp.data[0]
        
        if report.get("report_status") not in ["finalized", "approved", "distributed"]:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot distribute report with status '{report.get('report_status')}'. Report must be finalized or approved."
            )

        distribution_data = {
            "audit_report_id": audit_report_id,
            "distributed_to": distributed_to,
            "distribution_method": distribution_method,
            "distribution_format": distribution_format,
            "distributed_by": distributed_by,
            "external_reference": external_reference,
            "expiry_date": expiry_date.isoformat() if expiry_date else None,
            "is_active": True,
            "download_count": 0,
            "distributed_at": datetime.now(timezone.utc).isoformat()
        }

        resp = (
            supabase
            .table(settings.supabase_table_audit_report_distributions)
            .insert(distribution_data)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase audit report distribution creation failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create audit report distribution: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(
                status_code=500,
                detail="Failed to create audit report distribution: No data returned from database"
            )
        
        created_distribution = resp.data[0]

        current_distributed_to = report.get("distributed_to", [])
        if distributed_to not in current_distributed_to:
            current_distributed_to.append(distributed_to)

        update_data = {
            "distributed_to": current_distributed_to,
            "last_modified_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        if report.get("report_status") in ["approved", "finalized"]:
            update_data["report_status"] = "distributed"
        
        supabase.table(settings.supabase_table_audit_reports).update(update_data).eq("id", audit_report_id).execute()
        
        logger.info(f"Created distribution {created_distribution['id']} for report {audit_report_id}")
        return created_distribution
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create distribution for report {audit_report_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def log_distribution_access(
    distribution_id: str,
    access_ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> Dict[str, Any]:
    try:
        logger.info(f"Logging access for distribution {distribution_id}")

        distribution = get_audit_report_distribution_by_id(distribution_id)

        if not distribution.get("is_active", True):
            raise HTTPException(status_code=403, detail="Distribution is no longer active")

        expiry_date = distribution.get("expiry_date")
        if expiry_date:
            expiry_dt = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
            if datetime.now(timezone.utc) > expiry_dt:
                raise HTTPException(status_code=403, detail="Distribution has expired")

        current_time = datetime.now(timezone.utc).isoformat()
        update_data = {
            "download_count": distribution.get("download_count", 0) + 1,
            "last_accessed_at": current_time,
            "access_ip_address": access_ip_address
        }

        if not distribution.get("accessed_at"):
            update_data["accessed_at"] = current_time
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_distributions)
            .update(update_data)
            .eq("id", distribution_id)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Failed to log distribution access", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to log access: {resp.error.message}"
            )
        
        logger.info(f"Logged access for distribution {distribution_id} (total downloads: {update_data['download_count']})")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to log access for distribution {distribution_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def deactivate_distribution(distribution_id: str, deactivated_by: str) -> Dict[str, Any]:
    try:
        logger.info(f"Deactivating distribution {distribution_id}")
        
        update_data = {
            "is_active": False,
            "last_accessed_at": datetime.now(timezone.utc).isoformat()
        }
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_distributions)
            .update(update_data)
            .eq("id", distribution_id)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase distribution deactivation failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to deactivate distribution: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Distribution {distribution_id} not found")
        
        logger.info(f"Deactivated distribution {distribution_id}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to deactivate distribution {distribution_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def reactivate_distribution(distribution_id: str, reactivated_by: str) -> Dict[str, Any]:
    try:
        logger.info(f"Reactivating distribution {distribution_id}")
        
        # Check if distribution has expired
        distribution = get_audit_report_distribution_by_id(distribution_id)
        expiry_date = distribution.get("expiry_date")
        if expiry_date:
            expiry_dt = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
            if datetime.now(timezone.utc) > expiry_dt:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot reactivate expired distribution. Create a new distribution instead."
                )
        
        update_data = {
            "is_active": True
        }
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_distributions)
            .update(update_data)
            .eq("id", distribution_id)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase distribution reactivation failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to reactivate distribution: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Distribution {distribution_id} not found")
        
        logger.info(f"Reactivated distribution {distribution_id}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reactivate distribution {distribution_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def update_distribution_expiry(
    distribution_id: str,
    new_expiry_date: Optional[datetime],
    updated_by: str
) -> Dict[str, Any]:

    try:
        logger.info(f"Updating expiry date for distribution {distribution_id}")
        
        update_data = {
            "expiry_date": new_expiry_date.isoformat() if new_expiry_date else None
        }

        if new_expiry_date is None or new_expiry_date > datetime.now(timezone.utc):
            update_data["is_active"] = True
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_distributions)
            .update(update_data)
            .eq("id", distribution_id)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase distribution expiry update failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to update distribution expiry: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Distribution {distribution_id} not found")
        
        logger.info(f"Updated expiry date for distribution {distribution_id}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update expiry for distribution {distribution_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_distribution_statistics(
    audit_report_id: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
) -> Dict[str, Any]:
    try:
        logger.info("Generating distribution statistics")
        
        query = supabase.table(settings.supabase_table_audit_report_distributions).select("*")

        if audit_report_id:
            query = query.eq("audit_report_id", audit_report_id)
        if start_date:
            query = query.gte("distributed_at", start_date.isoformat())
        if end_date:
            query = query.lte("distributed_at", end_date.isoformat())
        
        resp = query.execute()
        distributions = resp.data

        total_distributions = len(distributions)
        active_distributions = len([d for d in distributions if d.get("is_active", True)])
        expired_distributions = 0
        total_downloads = sum(d.get("download_count", 0) for d in distributions)

        now = datetime.now(timezone.utc)
        for dist in distributions:
            expiry_date = dist.get("expiry_date")
            if expiry_date:
                expiry_dt = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
                if now > expiry_dt:
                    expired_distributions += 1

        method_counts = {}
        format_counts = {}
        
        for dist in distributions:
            method = dist.get("distribution_method", "unknown")
            method_counts[method] = method_counts.get(method, 0) + 1
            
            format_type = dist.get("distribution_format", "unknown")
            format_counts[format_type] = format_counts.get(format_type, 0) + 1

        avg_downloads_per_distribution = total_downloads / total_distributions if total_distributions > 0 else 0

        unique_recipients = len(set(d.get("distributed_to") for d in distributions if d.get("distributed_to")))
        
        stats = {
            "total_distributions": total_distributions,
            "active_distributions": active_distributions,
            "expired_distributions": expired_distributions,
            "deactivated_distributions": total_distributions - active_distributions - expired_distributions,
            "total_downloads": total_downloads,
            "avg_downloads_per_distribution": round(avg_downloads_per_distribution, 2),
            "unique_recipients": unique_recipients,
            "distributions_by_method": method_counts,
            "distributions_by_format": format_counts,
            "filters_applied": {
                "audit_report_id": audit_report_id,
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None
            }
        }
        
        logger.info(f"Generated statistics for {total_distributions} distributions")
        return stats
        
    except Exception as e:
        logger.error("Failed to generate distribution statistics", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def bulk_distribute_report(
    audit_report_id: str,
    recipients: List[str],
    distribution_method: str,
    distribution_format: str,
    distributed_by: str,
    expiry_date: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Bulk distributing report {audit_report_id} to {len(recipients)} recipients")
        
        created_distributions = []
        
        for recipient in recipients:
            try:
                distribution = create_audit_report_distribution(
                    audit_report_id=audit_report_id,
                    distributed_to=recipient,
                    distribution_method=distribution_method,
                    distribution_format=distribution_format,
                    distributed_by=distributed_by,
                    expiry_date=expiry_date
                )
                created_distributions.append(distribution)
                logger.info(f"Successfully distributed to {recipient}")
            except Exception as e:
                logger.error(f"Failed to distribute to {recipient}: {e}")
                # Continue with other recipients even if one fails
                created_distributions.append({
                    "error": str(e),
                    "recipient": recipient,
                    "status": "failed"
                })
        
        logger.info(f"Bulk distribution complete: {len([d for d in created_distributions if 'error' not in d])} successful, {len([d for d in created_distributions if 'error' in d])} failed")
        return created_distributions
        
    except Exception as e:
        logger.error(f"Failed to bulk distribute report {audit_report_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Bulk distribution failed: {e}")

def delete_distribution(distribution_id: str) -> Dict[str, Any]:
    try:
        logger.info(f"Deleting distribution {distribution_id}")
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_distributions)
            .delete()
            .eq("id", distribution_id)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase distribution deletion failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to delete distribution: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Distribution {distribution_id} not found")
        
        logger.info(f"Deleted distribution {distribution_id}")
        return {"message": f"Distribution {distribution_id} deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete distribution {distribution_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_expired_distributions() -> List[Dict[str, Any]]:
    try:
        logger.info("Fetching expired distributions")
        
        current_time = datetime.now(timezone.utc).isoformat()
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_report_distributions)
            .select("*")
            .eq("is_active", True)
            .lt("expiry_date", current_time)
            .execute()
        )
        
        logger.info(f"Found {len(resp.data)} expired distributions")
        return resp.data
        
    except Exception as e:
        logger.error("Failed to fetch expired distributions", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def cleanup_expired_distributions() -> Dict[str, Any]:
    try:
        logger.info("Cleaning up expired distributions")
        
        expired_distributions = get_expired_distributions()
        
        if not expired_distributions:
            return {"message": "No expired distributions found", "deactivated_count": 0}
        
        # Deactivate each expired distribution
        deactivated_count = 0
        for distribution in expired_distributions:
            try:
                deactivate_distribution(distribution["id"], "system_cleanup")
                deactivated_count += 1
            except Exception as e:
                logger.error(f"Failed to deactivate expired distribution {distribution['id']}: {e}")
        
        logger.info(f"Cleanup complete: deactivated {deactivated_count} expired distributions")
        return {
            "message": f"Successfully deactivated {deactivated_count} expired distributions",
            "deactivated_count": deactivated_count,
            "total_expired": len(expired_distributions)
        }
        
    except Exception as e:
        logger.error("Failed to cleanup expired distributions", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {e}")

def get_distribution_access_summary(distribution_id: str) -> Dict[str, Any]:
    try:
        logger.info(f"Getting access summary for distribution {distribution_id}")
        
        distribution = get_audit_report_distribution_by_id(distribution_id)

        access_summary = {
            "distribution_id": distribution_id,
            "distributed_to": distribution.get("distributed_to"),
            "distribution_method": distribution.get("distribution_method"),
            "distribution_format": distribution.get("distribution_format"),
            "distributed_at": distribution.get("distributed_at"),
            "expiry_date": distribution.get("expiry_date"),
            "is_active": distribution.get("is_active", True),
            "download_count": distribution.get("download_count", 0),
            "first_accessed_at": distribution.get("accessed_at"),
            "last_accessed_at": distribution.get("last_accessed_at"),
            "access_ip_address": distribution.get("access_ip_address")
        }

        if distribution.get("expiry_date"):
            expiry_dt = datetime.fromisoformat(distribution["expiry_date"].replace('Z', '+00:00'))
            access_summary["is_expired"] = datetime.now(timezone.utc) > expiry_dt
        else:
            access_summary["is_expired"] = False

        if access_summary["first_accessed_at"] and access_summary["last_accessed_at"]:
            first_access = datetime.fromisoformat(access_summary["first_accessed_at"].replace('Z', '+00:00'))
            last_access = datetime.fromisoformat(access_summary["last_accessed_at"].replace('Z', '+00:00'))
            time_span = (last_access - first_access).total_seconds()
            
            if time_span > 0 and access_summary["download_count"] > 1:
                access_summary["avg_access_interval_hours"] = round(time_span / 3600 / (access_summary["download_count"] - 1), 2)
            else:
                access_summary["avg_access_interval_hours"] = None
        else:
            access_summary["avg_access_interval_hours"] = None
        
        logger.info(f"Generated access summary for distribution {distribution_id}")
        return access_summary
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get access summary for distribution {distribution_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")