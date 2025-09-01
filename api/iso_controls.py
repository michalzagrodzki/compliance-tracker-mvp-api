from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Query, Path, HTTPException

from auth.decorators import ValidatedUser, authorize
from dependencies import ISOControlServiceDep
from entities.iso_control import ISOControlFilter
from common.exceptions import (
    ValidationException,
    BusinessLogicException,
    AuthorizationException
)
from common.logging import get_logger

router = APIRouter(prefix="/iso-controls", tags=["ISO Controls"])
logger = get_logger("iso_controls_api")


@router.get("",
    summary="List ISO controls with pagination",
    description="Get paginated list of ISO 27001 controls",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer", "reader"], check_active=True)
async def get_iso_controls(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    name_filter: Optional[str] = Query(None, description="Filter by ISO control name (partial match)"),
    current_user: ValidatedUser = None,
    iso_control_service: ISOControlServiceDep = None
) -> List[Dict[str, Any]]:
    try:
        filters = ISOControlFilter(name=name_filter) if name_filter else None
        controls = await iso_control_service.list_controls(
            user_id=current_user.id,
            skip=skip,
            limit=limit,
            filters=filters
        )
        return [control.to_dict() for control in controls]
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to list ISO controls: {e}")
        raise HTTPException(status_code=400 if isinstance(e, ValidationException) else 403, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error listing ISO controls: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error listing ISO controls: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")
