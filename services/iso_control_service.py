"""
ISO Control service using Repository pattern.
Trimmed to only support the list endpoint used by the API.
"""

from typing import Optional, List

from entities.iso_control import (
    ISOControl,
    ISOControlFilter,
)
from repositories.iso_control_repository import ISOControlRepository
from repositories.user_repository import UserRepository
from common.exceptions import (
    ValidationException,
    BusinessLogicException,
)
from common.logging import get_logger, log_performance

logger = get_logger("iso_control_service")


class ISOControlService:
    """Business logic for ISO control listing."""

    def __init__(self, iso_control_repository: ISOControlRepository, user_repository: UserRepository):
        self.control_repository = iso_control_repository
        self.user_repository = user_repository

    async def list_controls(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[ISOControlFilter] = None,
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
                    value=user_id,
                )

            # Get controls (no domain-based filtering for ISO controls)
            controls = await self.control_repository.list(skip, limit, filters)

            # Log performance
            duration_ms = (time.time() - start_time) * 1000
            log_performance(
                operation="list_iso_controls",
                duration_ms=duration_ms,
                success=True,
                item_count=len(controls),
            )

            return controls

        except ValidationException:
            raise
        except Exception as e:
            logger.error(f"Failed to list ISO controls: {e}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve ISO controls",
                error_code="ISO_CONTROL_LIST_FAILED",
            )


# Factory function
def create_iso_control_service(
    iso_control_repository: ISOControlRepository, user_repository: UserRepository
) -> ISOControlService:
    """Factory function to create ISOControlService instance."""
    return ISOControlService(iso_control_repository, user_repository)
