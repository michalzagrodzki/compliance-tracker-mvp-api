"""
User repository implementation using Supabase.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from repositories.base import SupabaseRepository
from entities.user import User, UserCreate, UserUpdate, UserFilter
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException
)
from common.logging import get_logger

logger = get_logger("user_repository")


class UserRepository(SupabaseRepository[User]):
    """
    Repository for User entity operations with Supabase.
    """

    def __init__(self, supabase_client, table_name: str = "users"):
        super().__init__(supabase_client, table_name)

    async def create(self, user_create: UserCreate) -> User:
        """Create a new user."""
        try:
            # Convert to dict and add audit fields
            user_data = user_create.model_dump()
            user_data = self._add_audit_fields(user_data, is_update=False)
            
            # Insert into database
            result = self.supabase.table(self.table_name).insert(user_data).execute()
            
            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to create user",
                    error_code="USER_CREATION_FAILED"
                )
            
            # Convert back to User entity
            created_user = User.from_dict(result.data[0])
            
            logger.info(f"Created user: {created_user.email} (ID: {created_user.id})")
            return created_user
            
        except Exception as e:
            logger.error(f"Failed to create user {user_create.email}: {e}", exc_info=True)
            if "duplicate key value" in str(e).lower():
                raise ValidationException(
                    detail="User with this email already exists",
                    field="email",
                    value=user_create.email
                )
            raise BusinessLogicException(
                detail="Failed to create user",
                error_code="USER_CREATION_FAILED",
                context={"email": user_create.email}
            )

    async def get_by_id(self, user_id: str) -> Optional[User]:
        """Retrieve a user by ID."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("id", user_id)\
                .execute()
            
            if not result.data:
                return None
            
            return User.from_dict(result.data[0])
            
        except Exception as e:
            logger.error(f"Failed to get user by ID {user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve user",
                error_code="USER_RETRIEVAL_FAILED",
                context={"user_id": user_id}
            )

    async def get_by_email(self, email: str) -> Optional[User]:
        """Retrieve a user by email address."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .eq("email", email)\
                .execute()
            
            if not result.data:
                return None
            
            return User.from_dict(result.data[0])
            
        except Exception as e:
            logger.error(f"Failed to get user by email {email}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve user",
                error_code="USER_RETRIEVAL_FAILED",
                context={"email": email}
            )

    async def update(self, user_id: str, update_data: UserUpdate) -> Optional[User]:
        """Update a user by ID."""
        try:
            # Check if user exists
            if not await self.exists(user_id):
                raise ResourceNotFoundException(
                    resource_type="User",
                    resource_id=user_id
                )
            
            # Convert update data to dict, excluding None values
            update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
            
            if not update_dict:
                # No changes to apply
                return await self.get_by_id(user_id)
            
            # Add audit fields
            update_dict = self._add_audit_fields(update_dict, is_update=True)
            
            # Update in database
            result = self.supabase.table(self.table_name)\
                .update(update_dict)\
                .eq("id", user_id)\
                .execute()
            
            if not result.data:
                raise BusinessLogicException(
                    detail="Failed to update user",
                    error_code="USER_UPDATE_FAILED"
                )
            
            updated_user = User.from_dict(result.data[0])
            logger.info(f"Updated user: {updated_user.email} (ID: {user_id})")
            return updated_user
            
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Failed to update user {user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update user",
                error_code="USER_UPDATE_FAILED",
                context={"user_id": user_id}
            )

    async def delete(self, user_id: str) -> bool:
        """Delete a user by ID (soft delete by deactivating)."""
        try:
            # Soft delete by deactivating the user
            update_data = UserUpdate(
                is_active=False,
                status="inactive"
            )
            
            updated_user = await self.update(user_id, update_data)
            
            if updated_user:
                logger.info(f"Soft deleted user: {updated_user.email} (ID: {user_id})")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete user {user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to delete user",
                error_code="USER_DELETION_FAILED",
                context={"user_id": user_id}
            )

    async def list(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[UserFilter] = None,
        order_by: Optional[str] = None
    ) -> List[User]:
        """List users with optional filtering and pagination."""
        try:
            query = self.supabase.table(self.table_name).select("*")
            
            # Apply filters
            if filters:
                filter_dict = {k: v for k, v in filters.model_dump().items() if v is not None}
                query = self._build_filters(query, filter_dict)
            
            # Apply ordering
            query = self._apply_ordering(query, order_by)
            
            # Apply pagination
            query = query.range(skip, skip + limit - 1)
            
            result = query.execute()
            
            # Convert to User entities
            users = [User.from_dict(user_data) for user_data in result.data]
            
            logger.debug(f"Listed {len(users)} users with filters: {filters}")
            return users
            
        except Exception as e:
            logger.error(f"Failed to list users: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve users",
                error_code="USER_LIST_FAILED"
            )

    async def update_login_info(self, user_id: str) -> Optional[User]:
        """Update user login information when they log in."""
        try:
            now = datetime.utcnow()
            
            # Get current user to increment login count
            current_user = await self.get_by_id(user_id)
            if not current_user:
                raise ResourceNotFoundException(
                    resource_type="User",
                    resource_id=user_id
                )
            
            # Update login info
            update_dict = {
                "last_login": now.isoformat(),
                "login_count": current_user.login_count + 1,
                "updated_at": now.isoformat()
            }
            
            result = self.supabase.table(self.table_name)\
                .update(update_dict)\
                .eq("id", user_id)\
                .execute()
            
            if not result.data:
                logger.warning(f"Failed to update login info for user {user_id}")
                return current_user
            
            updated_user = User.from_dict(result.data[0])
            logger.debug(f"Updated login info for user: {updated_user.email}")
            return updated_user
            
        except Exception as e:
            logger.error(f"Failed to update login info for user {user_id}: {e}", exc_info=True)
            # Don't raise exception for login info update failure
            return await self.get_by_id(user_id)

    async def get_by_compliance_domain(self, domain: str) -> List[User]:
        """Get all users with access to a specific compliance domain."""
        try:
            result = self.supabase.table(self.table_name)\
                .select("*")\
                .contains("compliance_domains", [domain])\
                .eq("is_active", True)\
                .execute()
            
            users = [User.from_dict(user_data) for user_data in result.data]
            
            logger.debug(f"Found {len(users)} users with access to domain: {domain}")
            return users
            
        except Exception as e:
            logger.error(f"Failed to get users by compliance domain {domain}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve users by compliance domain",
                error_code="USER_DOMAIN_RETRIEVAL_FAILED",
                context={"domain": domain}
            )

    async def get_active_users(self) -> List[User]:
        """Get all active users."""
        filters = UserFilter(is_active=True)
        return await self.list(filters=filters)

    async def get_users_by_role(self, role: str) -> List[User]:
        """Get all users with a specific role."""
        filters = UserFilter(role=role)
        return await self.list(filters=filters)