from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Query, Path, HTTPException

from auth.decorators import ValidatedUser, authorize
from dependencies import UserManagementServiceDep
from entities.user import UserUpdate
from auth.models import UserResponse
from common.exceptions import (
    ValidationException,
    ResourceNotFoundException,
    BusinessLogicException,
)

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "",
    summary="List all users with pagination",
    description="Fetches paginated users from the database.",
    response_model=List[UserResponse]
)
@authorize(allowed_roles=["admin"], check_active=True)
async def get_all_users_endpoint(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    user_service: UserManagementServiceDep = None,
) -> List[UserResponse]:
    try:
        users = await user_service.list_users(skip=skip, limit=limit, is_active=is_active)
        return [u.to_dict() for u in users]
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/{user_id}",
    summary="Get user by ID",
    description="Fetches a specific user by their ID.",
    response_model=UserResponse
)
@authorize(allowed_roles=["admin"], check_active=True)
async def get_user(
    user_id: str = Path(..., description="User UUID"),
    user_service: UserManagementServiceDep = None,
) -> UserResponse:
    try:
        user = await user_service.get_user_by_id(user_id)
        return user.to_dict()
    except ResourceNotFoundException as e:
        raise HTTPException(status_code=404, detail=str(e))
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch(
    "/{user_id}",
    summary="Update user profile",
    description="Updates a user's profile information.",
    response_model=UserResponse
)
@authorize(allowed_roles=["admin"], check_active=True)
async def update_user_profile(
    user_id: str,
    user_update: UserUpdate,
    current_user: ValidatedUser = None,
    user_service: UserManagementServiceDep = None,
) -> UserResponse:
    try:
        updated = await user_service.update_user(user_id, user_update, current_user.id)
        return updated.to_dict()
    except (ValidationException, ResourceNotFoundException) as e:
        raise HTTPException(status_code=400 if isinstance(e, ValidationException) else 404, detail=str(e))
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put(
    "/{user_id}/deactivate",
    summary="Deactivate user account",
    description="Deactivates a user account.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin"], check_active=True)
async def deactivate_user_account(
    user_id: str,
    current_user: ValidatedUser = None,
    user_service: UserManagementServiceDep = None,
) -> Dict[str, Any]:
    try:
        user = await user_service.deactivate_user(user_id, current_user.id)
        return user.to_dict()
    except ResourceNotFoundException as e:
        raise HTTPException(status_code=404, detail=str(e))
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put(
    "/{user_id}/activate",
    summary="Activate user account",
    description="Activates a user account.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin"], check_active=True)
async def activate_user_account(
    user_id: str,
    current_user: ValidatedUser = None,
    user_service: UserManagementServiceDep = None,
) -> Dict[str, Any]:
    try:
        user = await user_service.activate_user(user_id, current_user.id)
        return user.to_dict()
    except ResourceNotFoundException as e:
        raise HTTPException(status_code=404, detail=str(e))
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/role/{role_name}",
    summary="Get users by role",
    description="Fetches all users with a specific role.",
    response_model=List[UserResponse]
)
@authorize(allowed_roles=["admin"], check_active=True)
async def get_users_by_role_endpoint(
    role_name: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    user_service: UserManagementServiceDep = None,
) -> List[UserResponse]:
    try:
        users = await user_service.get_users_by_role(role_name, skip, limit)
        return [u.to_dict() for u in users]
    except ValidationException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/domain/{compliance_domain}",
    summary="Get users by compliance domain",
    description="Fetches all users associated with a specific compliance domain.",
    response_model=List[UserResponse]
)
@authorize(allowed_roles=["admin"], check_active=True)
async def get_users_by_domain_endpoint(
    compliance_domain: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
    user_service: UserManagementServiceDep = None,
) -> List[UserResponse]:
    try:
        users = await user_service.get_users_by_compliance_domain(compliance_domain, skip, limit)
        return [u.to_dict() for u in users]
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=str(e))
