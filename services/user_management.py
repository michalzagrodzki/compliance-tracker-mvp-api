import logging
import time
from typing import List, Dict, Any, Optional
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings
from pydantic import BaseModel, EmailStr
from datetime import datetime
try:
    import httpx
    import httpcore
except Exception:  # pragma: no cover - optional imports for type checks
    httpx = None
    httpcore = None

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    compliance_domains: Optional[List[str]] = None
    is_active: Optional[bool] = None

class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    role: str = "reader"
    compliance_domains: Optional[List[str]] = None
    is_active: bool = True

def list_users(skip: int = 0, limit: int = 10, role: Optional[str] = None, is_active: Optional[bool] = None) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching users: skip={skip}, limit={limit}, role={role}, is_active={is_active}")
        
        query = (
            supabase
            .table(settings.supabase_table_users)
            .select("id, email, full_name, role, compliance_domains, is_active, created_at, updated_at")
            .order("created_at", desc=True)
        )
        
        if role:
            query = query.eq("role", role)
        
        if is_active is not None:
            query = query.eq("is_active", is_active)
        
        resp = query.limit(limit).offset(skip).execute()
        
        logger.info(f"Received {len(resp.data)} users")
        return resp.data
    except Exception as e:
        logger.error("Failed to fetch users", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_user_by_id(user_id: str) -> Dict[str, Any]:
    """Fetch user with transient network retry to reduce spurious 5xx.

    Retries on httpx/httpcore ReadError a couple of times and refreshes the
    Supabase client between attempts.
    """
    global supabase
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(f"Fetching user with ID: {user_id}")
            resp = (
                supabase
                .table(settings.supabase_table_users)
                .select("id, email, full_name, role, compliance_domains, is_active, created_at, updated_at")
                .eq("id", user_id)
                .execute()
            )

            if not resp.data:
                raise HTTPException(status_code=404, detail=f"User with ID {user_id} not found")

            logger.info(f"Found user: {user_id}")
            return resp.data[0]

        except HTTPException:
            raise
        except Exception as e:
            is_read_error = False
            if httpx and isinstance(e, getattr(httpx, 'ReadError', tuple())):
                is_read_error = True
            if httpcore and isinstance(e, getattr(httpcore, 'ReadError', tuple())):
                is_read_error = True
            if not is_read_error and 'ReadError' not in str(type(e)) and 'Resource temporarily unavailable' not in str(e):
                logger.error(f"Failed to fetch user {user_id}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Database error: {e}")

            # Transient read error: retry with backoff and fresh client
            logger.warning(
                f"Transient read error fetching user {user_id} (attempt {attempt}/{max_attempts}); retrying..."
            )
            # Recreate the client to reset connections
            supabase = create_supabase_client()
            if attempt < max_attempts:
                time.sleep(0.2 * attempt)
            else:
                logger.error(f"Failed to fetch user {user_id} after retries", exc_info=True)
                raise HTTPException(status_code=503, detail="Temporary database read error, please retry")

def update_user(user_id: str, user_update: UserUpdate, updated_by: str) -> Dict[str, Any]:
    try:
        logger.info(f"Updating user {user_id}")
        
        update_data = {}
        
        if user_update.full_name is not None:
            update_data["full_name"] = user_update.full_name
        
        if user_update.role is not None:
            allowed_roles = ["admin", "compliance_officer", "reader"]
            if user_update.role not in allowed_roles:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid role. Must be one of: {', '.join(allowed_roles)}"
                )
            update_data["role"] = user_update.role
        
        if user_update.compliance_domains is not None:
            update_data["compliance_domains"] = user_update.compliance_domains
        
        if user_update.is_active is not None:
            update_data["is_active"] = user_update.is_active
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No update data provided")
        
        update_data["updated_at"] = datetime.now().isoformat()
        
        resp = (
            supabase
            .table(settings.supabase_table_users)
            .update(update_data)
            .eq("id", user_id)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        
        logger.info(f"Updated user {user_id} by {updated_by}")
        return resp.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update user {user_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def deactivate_user(user_id: str, updated_by: str) -> Dict[str, Any]:
    try:
        logger.info(f"Deactivating user {user_id}")
        
        update_data = {
            "is_active": False,
            "updated_at": datetime.now().isoformat()
        }
        
        resp = (
            supabase
            .table(settings.supabase_table_users)
            .update(update_data)
            .eq("id", user_id)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        
        logger.info(f"Deactivated user {user_id} by {updated_by}")
        return resp.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to deactivate user {user_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def activate_user(user_id: str, updated_by: str) -> Dict[str, Any]:
    try:
        logger.info(f"Activating user {user_id}")
        
        update_data = {
            "is_active": True,
            "updated_at": datetime.now().isoformat()
        }
        
        resp = (
            supabase
            .table(settings.supabase_table_users)
            .update(update_data)
            .eq("id", user_id)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        
        logger.info(f"Activated user {user_id} by {updated_by}")
        return resp.data[0]
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to activate user {user_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_users_by_role(role: str, skip: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching users with role: {role}")
        resp = (
            supabase
            .table(settings.supabase_table_users)
            .select("id, email, full_name, role, compliance_domains, is_active, created_at")
            .eq("role", role)
            .eq("is_active", True)
            .order("full_name")
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        logger.info(f"Found {len(resp.data)} users with role {role}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch users by role {role}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_users_by_compliance_domain(domain: str, skip: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching users with access to domain: {domain}")
        resp = (
            supabase
            .table(settings.supabase_table_users)
            .select("id, email, full_name, role, compliance_domains, is_active")
            .contains("compliance_domains", [domain])
            .eq("is_active", True)
            .order("full_name")
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        logger.info(f"Found {len(resp.data)} users with access to domain {domain}")
        return resp.data
    except Exception as e:
        logger.error(f"Failed to fetch users by domain {domain}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
