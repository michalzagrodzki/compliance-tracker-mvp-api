from fastapi import APIRouter, Depends
from fastapi.security import HTTPAuthorizationCredentials

from auth.decorators import ValidatedUser, authorize
from services.authentication import (
    auth_service,
    UserSignup,
    UserLogin,
    TokenResponse,
    RefreshTokenRequest,
    UserResponse,
    get_current_user,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/signup",
    response_model=TokenResponse,
    summary="Register a new user",
    description="Create a new user account with email and password",
    status_code=201
)
def signup(user_data: UserSignup):
    return auth_service.signup(user_data)


@router.post("/login",
    response_model=TokenResponse,
    summary="Login user",
    description="Authenticate user with email and password"
)
def login(login_data: UserLogin):
    return auth_service.login(login_data)


@router.post("/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Get a new access token using refresh token"
)
@authorize(check_active=True)
def refresh_token(refresh_data: RefreshTokenRequest):
    return auth_service.refresh_token(refresh_data)


@router.post("/logout",
    summary="Logout user",
    description="Logout user and invalidate tokens"
)
def logout(credentials: HTTPAuthorizationCredentials = Depends(get_current_user)):
    return auth_service.logout(credentials.credentials)


@router.get("/me",
    response_model=UserResponse,
    summary="Get current user profile",
    description="Get the profile of the currently authenticated user"
)
@authorize(allowed_roles=["admin", "compliance_officer", "reader"], check_active=True)
def get_me(current_user: ValidatedUser = None):
    return current_user