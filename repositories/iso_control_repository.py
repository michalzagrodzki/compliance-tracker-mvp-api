"""
ISO Control repository implementation using Supabase.
"""
from typing import Optional, List

from repositories.base import SupabaseRepository
from entities.iso_control import (
    ISOControl, 
    ISOControlFilter
)
from common.exceptions import (
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
