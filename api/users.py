from typing import Any, List, Dict, Optional
from fastapi import APIRouter, Query, Path

from auth.decorators import ValidatedUser, authorize
from services.user_management import (
    list_users,
    get_user_by_id,
    update_user,
    deactivate_user,
    activate_user,
    get_users_by_role,
    get_users_by_compliance_domain,
)
from auth.models import UserResponse
from services.user_management import UserUpdate

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("",
    summary="List all users with pagination",
    description="Fetches paginated users from the database.",
    response_model=List[UserResponse]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_all_users_endpoint(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
) -> List[UserResponse]:
    return list_users(skip=skip, limit=limit, is_active=is_active)


@router.get("/{user_id}",
    summary="Get user by ID",
    description="Fetches a specific user by their ID.",
    response_model=UserResponse
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_user(
    user_id: str = Path(..., description="User UUID"),
) -> UserResponse:
    return get_user_by_id(user_id)


@router.patch("/{user_id}",
    summary="Update user profile",
    description="Updates a user's profile information.",
    response_model=UserResponse
)
@authorize(allowed_roles=["admin"], check_active=True)
def update_user_profile(
    user_id: str,
    user_update: UserUpdate,
    current_user: ValidatedUser = None
) -> UserResponse:
    return update_user(user_id, user_update, current_user.id)


@router.put("/{user_id}/deactivate",
    summary="Deactivate user account",
    description="Deactivates a user account.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin"], check_active=True)
def deactivate_user_account(
    user_id: str,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return deactivate_user(user_id, current_user.id)


@router.put("/{user_id}/activate",
    summary="Activate user account",
    description="Activates a user account.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin"], check_active=True)
def activate_user_account(
    user_id: str,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return activate_user(user_id, current_user.id)


@router.get("/role/{role_name}",
    summary="Get users by role",
    description="Fetches all users with a specific role.",
    response_model=List[UserResponse]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_users_by_role_endpoint(
    role_name: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
) -> List[UserResponse]:
    return get_users_by_role(role_name, skip, limit)


@router.get("/domain/{compliance_domain}",
    summary="Get users by compliance domain",
    description="Fetches all users associated with a specific compliance domain.",
    response_model=List[UserResponse]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_users_by_domain_endpoint(
    compliance_domain: str,
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(50, ge=1, le=100, description="Maximum number of records to return"),
) -> List[UserResponse]:
    return get_users_by_compliance_domain(compliance_domain, skip, limit)