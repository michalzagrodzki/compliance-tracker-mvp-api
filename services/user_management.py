"""
User Management service using Repository pattern.
"""

from typing import List, Optional

from entities.user import (
    User,
    UserUpdate,
    UserFilter,
    UserRole,
    UserStatus,
)
from repositories.user_repository import UserRepository
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException,
)
from common.logging import get_logger, log_business_event

logger = get_logger("user_management_service")


class UserManagementService:
    """
    User Management service using Repository pattern.
    Handles business logic for user management.
    """

    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository

    async def list_users(
        self,
        skip: int = 0,
        limit: int = 10,
        role: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> List[User]:
        """List users with optional filters and pagination."""
        try:
            filters = UserFilter()
            if role is not None:
                try:
                    filters.role = UserRole(role)
                except ValueError:
                    raise ValidationException(
                        detail=f"Invalid role: {role}",
                        field="role",
                        value=role,
                    )
            if is_active is not None:
                filters.is_active = is_active

            users = await self.user_repository.list(
                skip=skip, limit=limit, filters=filters, order_by="-created_at"
            )
            return users
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to list users: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve users",
                error_code="USER_LIST_FAILED",
            )

    async def get_user_by_id(self, user_id: str) -> User:
        """Get a user by ID."""
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ResourceNotFoundException(resource_type="User", resource_id=user_id)
            return user
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Failed to get user {user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve user",
                error_code="USER_RETRIEVAL_FAILED",
                context={"user_id": user_id},
            )

    async def update_user(
        self, user_id: str, user_update: UserUpdate, updated_by: str
    ) -> User:
        """Update a user's profile."""
        try:
            # Normalize role if provided as string
            if user_update.role is not None and isinstance(user_update.role, str):
                try:
                    user_update.role = UserRole(user_update.role)
                except ValueError:
                    raise ValidationException(
                        detail=f"Invalid role: {user_update.role}",
                        field="role",
                        value=user_update.role,
                    )

            updated_user = await self.user_repository.update(user_id, user_update)

            # Business event log
            log_business_event(
                event_type="USER_UPDATED",
                entity_type="user",
                entity_id=user_id,
                action="update",
                user_id=updated_by,
                details={k: v for k, v in user_update.model_dump().items() if v is not None},
            )

            return updated_user
        except (ValidationException, ResourceNotFoundException):
            raise
        except Exception as e:
            logger.error(f"Failed to update user {user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update user",
                error_code="USER_UPDATE_FAILED",
                context={"user_id": user_id},
            )

    async def deactivate_user(self, user_id: str, updated_by: str) -> User:
        """Deactivate a user account (soft delete)."""
        try:
            update = UserUpdate(is_active=False, status=UserStatus.INACTIVE)
            user = await self.user_repository.update(user_id, update)

            log_business_event(
                event_type="USER_DEACTIVATED",
                entity_type="user",
                entity_id=user_id,
                action="deactivate",
                user_id=updated_by,
            )
            return user
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Failed to deactivate user {user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to deactivate user",
                error_code="USER_DEACTIVATION_FAILED",
                context={"user_id": user_id},
            )

    async def activate_user(self, user_id: str, updated_by: str) -> User:
        """Activate a user account."""
        try:
            update = UserUpdate(is_active=True, status=UserStatus.ACTIVE)
            user = await self.user_repository.update(user_id, update)

            log_business_event(
                event_type="USER_ACTIVATED",
                entity_type="user",
                entity_id=user_id,
                action="activate",
                user_id=updated_by,
            )
            return user
        except ResourceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Failed to activate user {user_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to activate user",
                error_code="USER_ACTIVATION_FAILED",
                context={"user_id": user_id},
            )

    async def get_users_by_role(
        self, role: str, skip: int = 0, limit: int = 50
    ) -> List[User]:
        """Get users by role (active users)."""
        try:
            try:
                role_enum = UserRole(role)
            except ValueError:
                raise ValidationException(
                    detail=f"Invalid role: {role}", field="role", value=role
                )
            filters = UserFilter(role=role_enum, is_active=True)
            users = await self.user_repository.list(
                skip=skip, limit=limit, filters=filters, order_by="full_name"
            )
            return users
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to get users by role {role}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve users by role",
                error_code="USER_ROLE_RETRIEVAL_FAILED",
                context={"role": role},
            )

    async def get_users_by_compliance_domain(
        self, domain: str, skip: int = 0, limit: int = 50
    ) -> List[User]:
        """Get users with access to a specific compliance domain (active users)."""
        try:
            users = await self.user_repository.get_by_compliance_domain(domain)
            # Order and paginate manually since repository returns full list
            users = sorted(users, key=lambda u: u.full_name)
            return users[skip : skip + limit]
        except Exception as e:
            logger.error(
                f"Failed to get users by compliance domain {domain}: {e}",
                exc_info=True,
            )
            raise BusinessLogicException(
                detail="Failed to retrieve users by compliance domain",
                error_code="USER_DOMAIN_RETRIEVAL_FAILED",
                context={"domain": domain},
            )


# Factory function
def create_user_management_service(user_repository: UserRepository) -> UserManagementService:
    """Factory function to create UserManagementService instance."""
    return UserManagementService(user_repository)
