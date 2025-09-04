"""
ISO Control repository implementation using Supabase.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid

from repositories.base import SupabaseRepository
from entities.iso_control import (
    ISOControl,
    ISOControlFilter,
    ISOControlCreate,
    ISOControlUpdate,
)
from common.exceptions import (
    BusinessLogicException,
    ResourceNotFoundException,
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
        """Create a new ISO control entry."""
        try:
            control_id = str(uuid.uuid4())
            now = datetime.utcnow().isoformat()

            payload: Dict[str, Any] = control_create.model_dump()
            payload.update({
                "id": control_id,
                "created_at": now,
                "updated_at": now,
            })

            result = self.supabase.table(self.table_name).insert(payload).execute()

            if not getattr(result, "data", None):
                raise BusinessLogicException(
                    detail="Failed to create ISO control",
                    error_code="ISO_CONTROL_CREATION_FAILED",
                )

            return ISOControl.from_dict(result.data[0])
        except Exception as e:
            logger.error(f"Failed to create ISO control: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create ISO control",
                error_code="ISO_CONTROL_CREATION_FAILED",
            )

    async def get_by_id(self, control_id: str) -> Optional[ISOControl]:
        """Retrieve a single ISO control by ID."""
        try:
            res = (
                self.supabase
                .table(self.table_name)
                .select("*")
                .eq("id", str(control_id))
                .limit(1)
                .execute()
            )
            if not getattr(res, "data", None):
                return None
            return ISOControl.from_dict(res.data[0])
        except Exception as e:
            logger.error(f"Failed to get ISO control {control_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve ISO control",
                error_code="ISO_CONTROL_RETRIEVAL_FAILED",
                context={"id": control_id} if isinstance(e, BusinessLogicException) else None,
            )

    async def update(self, control_id: str, update_data: ISOControlUpdate) -> Optional[ISOControl]:
        """Update an ISO control by ID."""
        try:
            # Ensure record exists
            if not await self.exists(str(control_id)):
                raise ResourceNotFoundException(
                    resource_type="ISOControl",
                    resource_id=str(control_id),
                )

            update_dict: Dict[str, Any] = {
                k: v for k, v in update_data.model_dump().items() if v is not None
            }
            if not update_dict:
                return await self.get_by_id(str(control_id))

            update_dict["updated_at"] = datetime.utcnow().isoformat()

            res = (
                self.supabase
                .table(self.table_name)
                .update(update_dict)
                .eq("id", str(control_id))
                .execute()
            )

            if not getattr(res, "data", None):
                raise BusinessLogicException(
                    detail="Failed to update ISO control",
                    error_code="ISO_CONTROL_UPDATE_FAILED",
                )

            return ISOControl.from_dict(res.data[0])
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Failed to update ISO control {control_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update ISO control",
                error_code="ISO_CONTROL_UPDATE_FAILED",
                context={"id": str(control_id)},
            )

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[ISOControlFilter] = None,
        order_by: Optional[str] = None
    ) -> List[ISOControl]:
        try:
            query = self.supabase.table(self.table_name).select("*")

            if filters:
                filter_dict = {}
                for field, value in filters.model_dump().items():
                    if value is not None:
                        if field == "name":
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

            query = self._apply_ordering(query, order_by or "name")

            query = query.range(skip, skip + limit - 1)
            
            result = query.execute()

            controls = [ISOControl.from_dict(control_data) for control_data in result.data]
            
            logger.debug(f"Listed {len(controls)} ISO controls with filters: {filters}")
            return controls
            
        except Exception as e:
            logger.error(f"Failed to list ISO controls: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve ISO controls",
                error_code="ISO_CONTROL_LIST_FAILED"
            )
