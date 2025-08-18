from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Query, Path

from auth.decorators import ValidatedUser, authorize
from services.iso_control import (
    list_iso_controls,
    get_iso_control_by_id,
    get_iso_control_by_name,
    create_iso_control,
    update_iso_control,
    delete_iso_control,
)
from services.schemas import CreateISOControlRequest, UpdateISOControlRequest

router = APIRouter(prefix="/iso-controls", tags=["ISO Controls"])


@router.get("",
    summary="List ISO controls with pagination",
    description="Get paginated list of ISO 27001 controls",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer", "reader"], check_active=True)
def get_iso_controls(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    name_filter: Optional[str] = Query(None, description="Filter by ISO control name (partial match)")
) -> List[Dict[str, Any]]:
    return list_iso_controls(skip=skip, limit=limit, name_filter=name_filter)


@router.get("/id/{control_id}",
    summary="Get ISO control by ID",
    description="Get detailed information about a specific ISO control by its ID",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer", "reader"], check_active=True)
def get_iso_control(
    control_id: str = Path(..., description="ISO control UUID")
) -> Dict[str, Any]:
    return get_iso_control_by_id(control_id)


@router.get("/name/{name}",
    summary="Get ISO control by name",
    description="Get detailed information about a specific ISO control by its name",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer", "reader"], check_active=True)
def get_iso_control_by_name_endpoint(
    name: str = Path(..., description="ISO control name")
) -> Dict[str, Any]:
    return get_iso_control_by_name(name)


@router.post("",
    summary="Create new ISO control",
    description="Create a new ISO 27001 control",
    response_model=Dict[str, Any],
    status_code=201
)
@authorize(allowed_roles=["admin"], check_active=True)
def create_iso_control_endpoint(
    request: CreateISOControlRequest
) -> Dict[str, Any]:
    return create_iso_control(request.dict())


@router.put("/{control_id}",
    summary="Update ISO control",
    description="Update an existing ISO 27001 control",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin"], check_active=True)
def update_iso_control_endpoint(
    request: UpdateISOControlRequest,
    control_id: str = Path(..., description="ISO control UUID")
) -> Dict[str, Any]:
    update_data = {k: v for k, v in request.dict().items() if v is not None}
    return update_iso_control(control_id, update_data)


@router.delete("/{control_id}",
    summary="Delete ISO control",
    description="Delete an ISO 27001 control",
    response_model=Dict[str, str]
)
@authorize(allowed_roles=["admin"], check_active=True)
def delete_iso_control_endpoint(
    control_id: str = Path(..., description="ISO control UUID")
) -> Dict[str, str]:
    return delete_iso_control(control_id)