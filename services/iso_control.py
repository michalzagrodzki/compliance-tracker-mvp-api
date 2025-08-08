import logging
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def list_iso_controls(
    skip: int = 0, 
    limit: int = 10,
    name_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Fetch paginated ISO controls from Supabase.
    Raises HTTPException on error.
    """
    try:
        logger.info(f"Fetching ISO controls: skip={skip}, limit={limit}")
        
        query = (
            supabase
            .table(settings.supabase_table_iso_controls)
            .select("id, name, controls, created_at, updated_at")
            .order("name", desc=False)
            .limit(limit)
            .offset(skip)
        )
        
        if name_filter:
            query = query.ilike("name", f"%{name_filter}%")
        
        resp = query.execute()
        
        logger.info(f"Received {len(resp.data)} ISO controls")
        return resp.data
        
    except Exception as e:
        logger.error("Failed to fetch ISO controls", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_iso_control_by_id(control_id: str) -> Dict[str, Any]:
    """
    Get ISO control by UUID.
    Raises HTTPException if not found or on error.
    """
    try:
        # Validate UUID format
        try:
            uuid.UUID(control_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid control_id format (must be UUID)")
        
        logger.info(f"Fetching ISO control with ID: {control_id}")
        resp = (
            supabase
            .table(settings.supabase_table_iso_controls)
            .select("*")
            .eq("id", control_id)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"ISO control with ID '{control_id}' not found")
        
        logger.info(f"Found ISO control: {control_id}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch ISO control {control_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_iso_control_by_name(name: str) -> Dict[str, Any]:
    """
    Get ISO control by name.
    Raises HTTPException if not found or on error.
    """
    try:
        logger.info(f"Fetching ISO control with name: {name}")
        resp = (
            supabase
            .table(settings.supabase_table_iso_controls)
            .select("*")
            .eq("name", name)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"ISO control with name '{name}' not found")
        
        logger.info(f"Found ISO control: {name}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch ISO control {name}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def create_iso_control(control_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a new ISO control.
    Raises HTTPException on validation error or database error.
    """
    try:
        logger.info(f"Creating ISO control: {control_data.get('name')}")
        
        # Validate required fields
        if "name" not in control_data or not control_data["name"]:
            raise HTTPException(status_code=400, detail="Name is required")
        
        # Validate name length (max 50 chars based on schema)
        if len(control_data["name"]) > 50:
            raise HTTPException(status_code=400, detail="Name must be 50 characters or less")
        
        # Check if name already exists
        try:
            existing = get_iso_control_by_name(control_data["name"])
            if existing:
                raise HTTPException(status_code=409, detail=f"ISO control with name '{control_data['name']}' already exists")
        except HTTPException as e:
            if e.status_code != 404:  # Only re-raise if it's not a "not found" error
                raise
        
        # Prepare data for insertion
        insert_data = {
            "name": control_data["name"].strip(),
            "controls": control_data.get("controls", {}),
        }
        
        # Validate controls is a dict
        if not isinstance(insert_data["controls"], dict):
            raise HTTPException(status_code=400, detail="Controls must be a JSON object")
        
        # Add timestamps (Supabase will handle these with defaults, but we can be explicit)
        current_time = datetime.now(timezone.utc).isoformat()
        insert_data["created_at"] = current_time
        insert_data["updated_at"] = current_time
        
        resp = (
            supabase
            .table(settings.supabase_table_iso_controls)
            .insert(insert_data)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase ISO control creation failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create ISO control: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(
                status_code=500,
                detail="Failed to create ISO control: No data returned from database"
            )
        
        logger.info(f"Created ISO control with ID: {resp.data[0]['id']}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create ISO control", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def update_iso_control(control_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update an existing ISO control.
    Raises HTTPException on validation error or database error.
    """
    try:
        # Validate UUID format
        try:
            uuid.UUID(control_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid control_id format (must be UUID)")
        
        logger.info(f"Updating ISO control {control_id}")
        
        # Prepare update data
        processed_data = {}
        
        # Handle name update with validation
        if "name" in update_data:
            name = update_data["name"]
            if not name or not name.strip():
                raise HTTPException(status_code=400, detail="Name cannot be empty")
            
            if len(name.strip()) > 50:
                raise HTTPException(status_code=400, detail="Name must be 50 characters or less")
            
            # Check if new name conflicts with existing control (excluding current one)
            try:
                existing = get_iso_control_by_name(name.strip())
                if existing and existing["id"] != control_id:
                    raise HTTPException(status_code=409, detail=f"ISO control with name '{name}' already exists")
            except HTTPException as e:
                if e.status_code != 404:  # Only re-raise if it's not a "not found" error
                    raise
            
            processed_data["name"] = name.strip()
        
        # Handle controls update with validation
        if "controls" in update_data:
            controls = update_data["controls"]
            if not isinstance(controls, dict):
                raise HTTPException(status_code=400, detail="Controls must be a JSON object")
            processed_data["controls"] = controls
        
        # Always update the timestamp
        processed_data["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        if not processed_data or len(processed_data) == 1:  # Only updated_at
            raise HTTPException(status_code=400, detail="No valid update data provided")
        
        resp = (
            supabase
            .table(settings.supabase_table_iso_controls)
            .update(processed_data)
            .eq("id", control_id)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase ISO control update failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to update ISO control: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"ISO control {control_id} not found")
        
        logger.info(f"Successfully updated ISO control {control_id}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update ISO control {control_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def delete_iso_control(control_id: str) -> Dict[str, str]:
    """
    Delete an ISO control by ID.
    Raises HTTPException if not found or on error.
    """
    try:
        # Validate UUID format
        try:
            uuid.UUID(control_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid control_id format (must be UUID)")
        
        logger.info(f"Deleting ISO control {control_id}")
        
        # First check if the control exists
        existing_control = get_iso_control_by_id(control_id)
        
        resp = (
            supabase
            .table(settings.supabase_table_iso_controls)
            .delete()
            .eq("id", control_id)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase ISO control deletion failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to delete ISO control: {resp.error.message}"
            )
        
        logger.info(f"Successfully deleted ISO control {control_id}")
        return {"message": f"ISO control '{existing_control['name']}' deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete ISO control {control_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")