"""
ISO Control service using Repository pattern.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from entities.iso_control import (
    ISOControl, 
    ISOControlCreate, 
    ISOControlUpdate, 
    ISOControlFilter
)
from repositories.iso_control_repository import ISOControlRepository
from repositories.user_repository import UserRepository
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException,
    AuthorizationException
)
from common.logging import get_logger, log_business_event, log_performance

logger = get_logger("iso_control_service")


class ISOControlService:
    """
    ISO Control service using Repository pattern.
    Handles business logic for ISO control management.
    """

    def __init__(self, iso_control_repository: ISOControlRepository, user_repository: UserRepository):
        self.control_repository = iso_control_repository
        self.user_repository = user_repository

    async def create_control(
        self, 
        control_create: ISOControlCreate, 
        user_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> ISOControl:
        """Create a new ISO control."""
        try:
            import time
            start_time = time.time()
            
            # Validate user exists and is active
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive user",
                    field="user_id",
                    value=user_id
                )
            
            # Check if user has admin access (only admins can create ISO controls)
            if not user.is_admin():
                raise AuthorizationException(
                    detail="Only administrators can create ISO controls",
                    error_code="ADMIN_ACCESS_REQUIRED"
                )
            
            # Create the control
            created_control = await self.control_repository.create(control_create)
            
            # Log business event
            log_business_event(
                event_type="ISO_CONTROL_CREATED",
                entity_type="iso_control",
                entity_id=created_control.id,
                action="create",
                user_id=user_id,
                details={
                    "control_name": created_control.name,
                    "has_controls_data": bool(created_control.controls),
                    "ip_address": ip_address,
                    "user_agent": user_agent
                }
            )
            
            # Log performance
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="create_iso_control",
                duration_ms=duration_ms,
                success=True,
                item_count=1
            )
            
            return created_control
            
        except (ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to create ISO control: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create ISO control",
                error_code="ISO_CONTROL_CREATION_FAILED",
                context={"control_name": control_create.name}
            )

    async def get_control_by_id(self, control_id: str, user_id: str) -> ISOControl:
        """Get an ISO control by ID with access control."""
        try:
            # Get the control
            control = await self.control_repository.get_by_id(control_id)
            if not control:
                raise ResourceNotFoundException(
                    resource_type="ISOControl",
                    resource_id=control_id
                )
            
            # Validate user exists (any authenticated user can read ISO controls)
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            return control
            
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception as e:
            logger.error(f"Failed to get ISO control {control_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve ISO control",
                error_code="ISO_CONTROL_RETRIEVAL_FAILED",
                context={"control_id": control_id}
            )

    async def get_control_by_name(self, name: str, user_id: str) -> ISOControl:
        """Get an ISO control by name with access control."""
        try:
            # Get the control
            control = await self.control_repository.get_by_name(name)
            if not control:
                raise ResourceNotFoundException(
                    resource_type="ISOControl",
                    resource_id=name
                )
            
            # Validate user exists (any authenticated user can read ISO controls)
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            return control
            
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception as e:
            logger.error(f"Failed to get ISO control by name {name}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve ISO control",
                error_code="ISO_CONTROL_NAME_RETRIEVAL_FAILED",
                context={"name": name}
            )

    async def update_control(self, control_id: str, control_update: ISOControlUpdate, user_id: str) -> ISOControl:
        """Update an ISO control."""
        try:
            # Validate user exists and has admin access
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive user",
                    field="user_id",
                    value=user_id
                )
            
            if not user.is_admin():
                raise AuthorizationException(
                    detail="Only administrators can update ISO controls",
                    error_code="ADMIN_ACCESS_REQUIRED"
                )
            
            # Verify control exists
            existing_control = await self.control_repository.get_by_id(control_id)
            if not existing_control:
                raise ResourceNotFoundException(
                    resource_type="ISOControl",
                    resource_id=control_id
                )
            
            # Update the control
            updated_control = await self.control_repository.update(control_id, control_update)
            if not updated_control:
                raise ResourceNotFoundException(
                    resource_type="ISOControl",
                    resource_id=control_id
                )
            
            # Log business event
            log_business_event(
                event_type="ISO_CONTROL_UPDATED",
                entity_type="iso_control",
                entity_id=control_id,
                action="update",
                user_id=user_id,
                details={
                    "updated_fields": list(control_update.model_dump(exclude_none=True).keys()),
                    "control_name": updated_control.name
                }
            )
            
            return updated_control
            
        except (ResourceNotFoundException, ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to update ISO control {control_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update ISO control",
                error_code="ISO_CONTROL_UPDATE_FAILED",
                context={"control_id": control_id}
            )

    async def delete_control(self, control_id: str, user_id: str) -> bool:
        """Delete an ISO control."""
        try:
            # Validate user exists and has admin access
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(
                    detail="Invalid or inactive user",
                    field="user_id",
                    value=user_id
                )
            
            if not user.is_admin():
                raise AuthorizationException(
                    detail="Only administrators can delete ISO controls",
                    error_code="ADMIN_ACCESS_REQUIRED"
                )
            
            # Get control for logging before deletion
            existing_control = await self.control_repository.get_by_id(control_id)
            if not existing_control:
                raise ResourceNotFoundException(
                    resource_type="ISOControl",
                    resource_id=control_id
                )
            
            # Delete the control
            success = await self.control_repository.delete(control_id)
            
            if success:
                # Log business event
                log_business_event(
                    event_type="ISO_CONTROL_DELETED",
                    entity_type="iso_control",
                    entity_id=control_id,
                    action="delete",
                    user_id=user_id,
                    details={
                        "control_name": existing_control.name
                    }
                )
            
            return success
            
        except (ResourceNotFoundException, ValidationException, AuthorizationException):
            raise
        except Exception as e:
            logger.error(f"Failed to delete ISO control {control_id}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to delete ISO control",
                error_code="ISO_CONTROL_DELETION_FAILED",
                context={"control_id": control_id}
            )

    async def list_controls(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[ISOControlFilter] = None
    ) -> List[ISOControl]:
        """List ISO controls with access control."""
        try:
            import time
            start_time = time.time()
            
            # Validate user exists (any authenticated user can read ISO controls)
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            # Get controls (no domain-based filtering for ISO controls)
            controls = await self.control_repository.list(skip, limit, filters)
            
            # Log performance
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="list_iso_controls",
                duration_ms=duration_ms,
                success=True,
                item_count=len(controls)
            )
            
            return controls
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to list ISO controls: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve ISO controls",
                error_code="ISO_CONTROL_LIST_FAILED"
            )

    async def search_controls_by_name(self, name_query: str, user_id: str, skip: int = 0, limit: int = 100) -> List[ISOControl]:
        """Search ISO controls by name with access control."""
        try:
            # Validate user exists
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            return await self.control_repository.search_by_name(name_query, skip, limit)
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to search ISO controls by name {name_query}: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to search ISO controls",
                error_code="ISO_CONTROL_SEARCH_FAILED",
                context={"name_query": name_query}
            )

    async def get_control_statistics(self, user_id: str) -> Dict[str, Any]:
        """Get ISO control statistics with access control."""
        try:
            # Validate user exists
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(
                    detail="Invalid user",
                    field="user_id",
                    value=user_id
                )
            
            return await self.control_repository.get_statistics()
            
        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to get ISO control statistics: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve ISO control statistics",
                error_code="ISO_CONTROL_STATISTICS_FAILED"
            )


# Factory function
def create_iso_control_service(
    iso_control_repository: ISOControlRepository,
    user_repository: UserRepository
) -> ISOControlService:
    """Factory function to create ISOControlService instance."""
    return ISOControlService(iso_control_repository, user_repository)