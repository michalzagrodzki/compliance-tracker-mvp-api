"""
Base repository interface and abstract classes for the Repository pattern.
"""

from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Optional, List, Dict, Any
from datetime import datetime

# Generic type for entity models
T = TypeVar('T')


class BaseRepository(ABC, Generic[T]):
    """
    Abstract base repository interface defining common CRUD operations.
    """

    @abstractmethod
    async def create(self, entity: T) -> T:
        """Create a new entity."""
        pass

    @abstractmethod
    async def get_by_id(self, entity_id: str) -> Optional[T]:
        """Retrieve an entity by its ID."""
        pass

    @abstractmethod
    async def update(self, entity_id: str, update_data: Dict[str, Any]) -> Optional[T]:
        """Update an entity by its ID."""
        pass

    @abstractmethod
    async def delete(self, entity_id: str) -> bool:
        """Delete an entity by its ID."""
        pass

    @abstractmethod
    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[Dict[str, Any]] = None,
        order_by: Optional[str] = None
    ) -> List[T]:
        """List entities with optional filtering and pagination."""
        pass

    @abstractmethod
    async def exists(self, entity_id: str) -> bool:
        """Check if an entity exists by its ID."""
        pass

    @abstractmethod
    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count entities with optional filtering."""
        pass


class SupabaseRepository(BaseRepository[T], ABC):
    """
    Base Supabase repository implementation with common functionality.
    """

    def __init__(self, supabase_client, table_name: str):
        self.supabase = supabase_client
        self.table_name = table_name

    def _add_audit_fields(self, data: Dict[str, Any], is_update: bool = False) -> Dict[str, Any]:
        """Add audit fields to entity data."""
        now = datetime.utcnow().isoformat()
        
        if not is_update:
            data["created_at"] = now
        
        data["updated_at"] = now
        return data

    def _build_filters(self, query, filters: Dict[str, Any]):
        """Apply filters to a Supabase query."""
        if not filters:
            return query
            
        for field, value in filters.items():
            if isinstance(value, list):
                query = query.in_(field, value)
            elif isinstance(value, dict):
                # Handle complex filters like ranges, comparisons
                for operator, filter_value in value.items():
                    if operator == "eq":
                        query = query.eq(field, filter_value)
                    elif operator == "neq":
                        query = query.neq(field, filter_value)
                    elif operator == "gt":
                        query = query.gt(field, filter_value)
                    elif operator == "gte":
                        query = query.gte(field, filter_value)
                    elif operator == "lt":
                        query = query.lt(field, filter_value)
                    elif operator == "lte":
                        query = query.lte(field, filter_value)
                    elif operator == "like":
                        query = query.like(field, filter_value)
                    elif operator == "ilike":
                        query = query.ilike(field, filter_value)
            else:
                query = query.eq(field, value)
        
        return query

    def _apply_ordering(self, query, order_by: Optional[str]):
        """Apply ordering to a Supabase query."""
        if order_by:
            if order_by.startswith("-"):
                # Descending order
                field = order_by[1:]
                query = query.order(field, desc=True)
            else:
                # Ascending order
                query = query.order(order_by, desc=False)
        else:
            # Default ordering by created_at desc
            query = query.order("created_at", desc=True)
        
        return query

    async def delete(self, entity_id: str) -> bool:
        """Default hard delete by ID.

        Concrete repositories can override this to implement soft-delete
        semantics when needed. Returns True if a record was deleted.
        """
        try:
            res = (
                self.supabase
                .table(self.table_name)
                .delete()
                .eq("id", entity_id)
                .execute()
            )
            # Supabase python client returns deleted rows in data
            return bool(getattr(res, "data", None))
        except Exception:
            # Mirror the defensive pattern used in exists()/count()
            return False

    async def exists(self, entity_id: str) -> bool:
        """Check if an entity exists by its ID."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("id")\
                .eq("id", entity_id)\
                .limit(1)\
                .execute()
            
            return bool(result.data)
        except Exception:
            return False

    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count entities with optional filtering."""
        try:
            query = self.supabase.table(self.table_name).select("id", count="exact")
            query = self._build_filters(query, filters or {})
            result = query.execute()
            
            return result.count or 0
        except Exception:
            return 0
