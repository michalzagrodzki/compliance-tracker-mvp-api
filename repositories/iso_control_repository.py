"""
ISO Control repository implementation using Supabase.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid

from repositories.base import SupabaseRepository
from entities.iso_control import (
    ISOControl, 
    ISOControlCreate, 
    ISOControlUpdate, 
    ISOControlFilter
)
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException
)
from common.logging import get_logger

logger = get_logger("iso_control_repository")


class ISOControlRepository(SupabaseRepository[ISOControl]):
    """
    Repository for ISOControl entity operations with Supabase.
    """

    def __init__(self, supabase_client, table_name: str = "iso_controls"):
        super().__init__(supabase_client, table_name)

    async def create(self, control_create: ISOControlCreate) -> ISOControl:
        """Create a new ISO control."""
        try:
            # Generate ID and timestamps
            control_id = str(uuid.uuid4())
            now = datetime.utcnow()
            
            # Convert to dict and add required fields
            control_data = control_create.model_dump()
            control_data.update({
                "id": control_id,
                "created_at": now.isoformat(),
                "updated_at": now.isoformat()
            })
            
            # Check if name already exists
            if await self.exists_by_name(control_data["name"]):
                raise ValidationException(
                    detail=f"ISO control with name '{control_data['name']}' already exists",
                    error_code="ISO_CONTROL_NAME_EXISTS"
                )
            
            # Insert into database
            result = self.supabase.table(self.table_name).insert(control_data).execute()
            
            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to create ISO control",
                    error_code="ISO_CONTROL_CREATION_FAILED"
                )
            
            # Convert back to ISOControl entity
            created_control = ISOControl.from_dict(result.data[0])
            
            logger.info(f"Created ISO control: {created_control.name} (ID: {created_control.id})")
            return created_control
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to create ISO control: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create ISO control",
                error_code="ISO_CONTROL_CREATION_FAILED",
                context={"name": control_create.name}
            )

    async def get_by_id(self, control_id: str) -> Optional[ISOControl]:
        """Retrieve an ISO control by ID."""
        try:
            # Validate UUID format
            try:
                uuid.UUID(control_id)
            except ValueError:
                raise ValidationException(
                    detail="Invalid control_id format (must be UUID)",
                    field="control_id",
                    value=control_id
                )
            
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("id", control_id)\
                .execute()
            
            if not result.data:
                return None
            
            return ISOControl.from_dict(result.data[0])
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to get ISO control by ID {control_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve ISO control",
                error_code="ISO_CONTROL_RETRIEVAL_FAILED",
                context={"control_id": control_id}
            )

    async def get_by_name(self, name: str) -> Optional[ISOControl]:
        """Retrieve an ISO control by name."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("name", name.strip())\
                .execute()
            
            if not result.data:
                return None
            
            return ISOControl.from_dict(result.data[0])
            
        except Exception as e:
            logger.error(f"Failed to get ISO control by name {name}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve ISO control",
                error_code="ISO_CONTROL_NAME_RETRIEVAL_FAILED",
                context={"name": name}
            )

    async def exists_by_name(self, name: str) -> bool:
        """Check if an ISO control with the given name exists."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("id")\
                .eq("name", name.strip())\
                .limit(1)\
                .execute()
            
            return bool(result.data)
            
        except Exception:
            return False

    async def update(self, control_id: str, update_data: ISOControlUpdate) -> Optional[ISOControl]:
        """Update an ISO control by ID."""
        try:
            # Validate UUID format
            try:
                uuid.UUID(control_id)
            except ValueError:
                raise ValidationException(
                    detail="Invalid control_id format (must be UUID)",
                    field="control_id",
                    value=control_id
                )
            
            # Check if control exists
            if not await self.exists(control_id):
                raise ResourceNotFoundException(
                    resource_type="ISOControl",
                    resource_id=control_id
                )
            
            # Convert update data to dict, excluding None values
            update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
            
            if not update_dict:
                # No changes to apply
                return await self.get_by_id(control_id)
            
            # Check for name conflicts if name is being updated
            if "name" in update_dict:
                existing_with_name = await self.get_by_name(update_dict["name"])
                if existing_with_name and existing_with_name.id != control_id:
                    raise ValidationException(
                        detail=f"ISO control with name '{update_dict['name']}' already exists",
                        error_code="ISO_CONTROL_NAME_EXISTS"
                    )
            
            # Add updated timestamp
            update_dict["updated_at"] = datetime.utcnow().isoformat()
            
            # Update in database
            result = self.supabase.table(self.table_name)\
                .update(update_dict)\
                .eq("id", control_id)\
                .execute()
            
            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to update ISO control",
                    error_code="ISO_CONTROL_UPDATE_FAILED"
                )
            
            updated_control = ISOControl.from_dict(result.data[0])
            logger.info(f"Updated ISO control: {updated_control.name} (ID: {control_id})")
            return updated_control
            
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception as e:
            logger.error(f"Failed to update ISO control {control_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update ISO control",
                error_code="ISO_CONTROL_UPDATE_FAILED",
                context={"control_id": control_id}
            )

    async def delete(self, control_id: str) -> bool:
        """Delete an ISO control by ID."""
        try:
            # Validate UUID format
            try:
                uuid.UUID(control_id)
            except ValueError:
                raise ValidationException(
                    detail="Invalid control_id format (must be UUID)",
                    field="control_id",
                    value=control_id
                )
            
            # Check if control exists first to get the name for logging
            existing_control = await self.get_by_id(control_id)
            if not existing_control:
                raise ResourceNotFoundException(
                    resource_type="ISOControl",
                    resource_id=control_id
                )
            
            result = self.supabase.table(self.table_name)\
                .delete()\
                .eq("id", control_id)\
                .execute()
            
            if result.data:
                logger.info(f"Deleted ISO control: {existing_control.name} (ID: {control_id})")
                return True
            
            return False
            
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception as e:
            logger.error(f"Failed to delete ISO control {control_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to delete ISO control",
                error_code="ISO_CONTROL_DELETION_FAILED",
                context={"control_id": control_id}
            )

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[ISOControlFilter] = None,
        order_by: Optional[str] = None
    ) -> List[ISOControl]:
        """List ISO controls with optional filtering and pagination."""
        try:
            query = self.supabase.table(self.table_name).select("*")
            
            # Apply filters
            if filters:
                filter_dict = {}
                for field, value in filters.model_dump().items():
                    if value is not None:
                        if field == "name":
                            # Use ilike for partial name matching
                            query = query.ilike("name", f"%{value}%")
                        elif field in ["created_after", "updated_after"]:
                            date_field = field.replace("_after", "_at")
                            query = query.gte(date_field, value.isoformat())
                        elif field in ["created_before", "updated_before"]:
                            date_field = field.replace("_before", "_at")
                            query = query.lte(date_field, value.isoformat())
                        else:
                            filter_dict[field] = value
                
                query = self._build_filters(query, filter_dict)
            
            # Apply ordering (default to name asc)
            query = self._apply_ordering(query, order_by or "name")
            
            # Apply pagination
            query = query.range(skip, skip + limit - 1)
            
            result = query.execute()
            
            # Convert to ISOControl entities
            controls = [ISOControl.from_dict(control_data) for control_data in result.data]
            
            logger.debug(f"Listed {len(controls)} ISO controls with filters: {filters}")
            return controls
            
        except Exception as e:
            logger.error(f"Failed to list ISO controls: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve ISO controls",
                error_code="ISO_CONTROL_LIST_FAILED"
            )

    async def search_by_name(self, name_query: str, skip: int = 0, limit: int = 100) -> List[ISOControl]:
        """Search ISO controls by name (partial match)."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .ilike("name", f"%{name_query}%")\
                .order("name", desc=False)\
                .range(skip, skip + limit - 1)\
                .execute()
            
            controls = [ISOControl.from_dict(control_data) for control_data in result.data]
            
            logger.debug(f"Found {len(controls)} ISO controls matching name query: {name_query}")
            return controls
            
        except Exception as e:
            logger.error(f"Failed to search ISO controls by name {name_query}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to search ISO controls",
                error_code="ISO_CONTROL_SEARCH_FAILED",
                context={"name_query": name_query}
            )

    async def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about ISO controls."""
        try:
            # Get total count
            total_result = self.supabase.table(self.table_name)\
                .select("id", count="exact")\
                .execute()
            
            total_controls = total_result.count or 0
            
            # Get controls with empty controls field
            empty_controls_result = self.supabase.table(self.table_name)\
                .select("id", count="exact")\
                .or_("controls.is.null,controls.eq.{}")\
                .execute()
            
            empty_controls = empty_controls_result.count or 0
            configured_controls = total_controls - empty_controls
            
            statistics = {
                "total_controls": total_controls,
                "configured_controls": configured_controls,
                "empty_controls": empty_controls,
                "configuration_rate_percent": (configured_controls / total_controls * 100) if total_controls > 0 else 0
            }
            
            logger.debug(f"Generated ISO control statistics: {statistics}")
            return statistics
            
        except Exception as e:
            logger.error(f"Failed to get ISO control statistics: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve ISO control statistics",
                error_code="ISO_CONTROL_STATISTICS_FAILED"
            )