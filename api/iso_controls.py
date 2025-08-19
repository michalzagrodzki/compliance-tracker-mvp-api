from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Query, Path, HTTPException

from auth.decorators import ValidatedUser, authorize
from dependencies import ISOControlServiceDep
from entities.iso_control import ISOControlCreate, ISOControlUpdate, ISOControlFilter
from services.schemas import CreateISOControlRequest, UpdateISOControlRequest
from common.exceptions import (
    ValidationException,
    ResourceNotFoundException,
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


@router.get("/id/{control_id}",
    summary="Get ISO control by ID",
    description="Get detailed information about a specific ISO control by its ID",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer", "reader"], check_active=True)
async def get_iso_control(
    control_id: str = Path(..., description="ISO control UUID"),
    current_user: ValidatedUser = None,
    iso_control_service: ISOControlServiceDep = None
) -> Dict[str, Any]:
    try:
        control = await iso_control_service.get_control_by_id(control_id, current_user.id)
        return control.to_dict()
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to get ISO control {control_id}: {e}")
        raise HTTPException(status_code=400 if isinstance(e, ValidationException) else 403, detail=str(e))
    except ResourceNotFoundException as e:
        logger.error(f"ISO control {control_id} not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error getting ISO control {control_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error getting ISO control {control_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/name/{name}",
    summary="Get ISO control by name",
    description="Get detailed information about a specific ISO control by its name",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer", "reader"], check_active=True)
async def get_iso_control_by_name_endpoint(
    name: str = Path(..., description="ISO control name"),
    current_user: ValidatedUser = None,
    iso_control_service: ISOControlServiceDep = None
) -> Dict[str, Any]:
    try:
        control = await iso_control_service.get_control_by_name(name, current_user.id)
        return control.to_dict()
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to get ISO control by name {name}: {e}")
        raise HTTPException(status_code=400 if isinstance(e, ValidationException) else 403, detail=str(e))
    except ResourceNotFoundException as e:
        logger.error(f"ISO control with name {name} not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error getting ISO control by name {name}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error getting ISO control by name {name}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("",
    summary="Create new ISO control",
    description="Create a new ISO 27001 control",
    response_model=Dict[str, Any],
    status_code=201
)
@authorize(allowed_roles=["admin"], check_active=True)
async def create_iso_control_endpoint(
    request: CreateISOControlRequest,
    current_user: ValidatedUser = None,
    iso_control_service: ISOControlServiceDep = None
) -> Dict[str, Any]:
    try:
        control_create = ISOControlCreate(**request.dict())
        control = await iso_control_service.create_control(control_create, current_user.id)
        return control.to_dict()
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to create ISO control: {e}")
        status_code = 409 if "already exists" in str(e) else (403 if isinstance(e, AuthorizationException) else 400)
        raise HTTPException(status_code=status_code, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error creating ISO control: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error creating ISO control: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/{control_id}",
    summary="Update ISO control",
    description="Update an existing ISO 27001 control",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin"], check_active=True)
async def update_iso_control_endpoint(
    request: UpdateISOControlRequest,
    control_id: str = Path(..., description="ISO control UUID"),
    current_user: ValidatedUser = None,
    iso_control_service: ISOControlServiceDep = None
) -> Dict[str, Any]:
    try:
        update_data = {k: v for k, v in request.dict().items() if v is not None}
        if not update_data:
            raise HTTPException(status_code=400, detail="No valid update data provided")
        
        control_update = ISOControlUpdate(**update_data)
        control = await iso_control_service.update_control(control_id, control_update, current_user.id)
        return control.to_dict()
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to update ISO control {control_id}: {e}")
        status_code = 409 if "already exists" in str(e) else (403 if isinstance(e, AuthorizationException) else 400)
        raise HTTPException(status_code=status_code, detail=str(e))
    except ResourceNotFoundException as e:
        logger.error(f"ISO control {control_id} not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error updating ISO control {control_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error updating ISO control {control_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/{control_id}",
    summary="Delete ISO control",
    description="Delete an ISO 27001 control",
    response_model=Dict[str, str]
)
@authorize(allowed_roles=["admin"], check_active=True)
async def delete_iso_control_endpoint(
    control_id: str = Path(..., description="ISO control UUID"),
    current_user: ValidatedUser = None,
    iso_control_service: ISOControlServiceDep = None
) -> Dict[str, str]:
    try:
        success = await iso_control_service.delete_control(control_id, current_user.id)
        if success:
            return {"message": "ISO control deleted successfully"}
        else:
            raise HTTPException(status_code=500, detail="Failed to delete ISO control")
    except (ValidationException, AuthorizationException) as e:
        logger.error(f"Failed to delete ISO control {control_id}: {e}")
        raise HTTPException(status_code=403 if isinstance(e, AuthorizationException) else 400, detail=str(e))
    except ResourceNotFoundException as e:
        logger.error(f"ISO control {control_id} not found: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except BusinessLogicException as e:
        logger.error(f"Business logic error deleting ISO control {control_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error deleting ISO control {control_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")