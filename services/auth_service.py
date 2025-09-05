"""
Refactored Authentication Service using Repository pattern.
"""

from typing import Optional
from fastapi import HTTPException

from supabase import Client
from auth.models import RefreshTokenRequest, TokenResponse, UserLogin, UserSignup
from entities.user import User, UserCreate
from repositories.user_repository import UserRepository
from common.exceptions import (
    AuthenticationException,
    ValidationException,
    ResourceNotFoundException,
    BusinessLogicException
)
from common.logging import get_logger
from config.config import settings

logger = get_logger("auth_service")


class AuthService:
    """
    Authentication service using Repository pattern.
    Handles authentication operations and user management.
    """

    def __init__(self, supabase_client: Client, user_repository: UserRepository):
        self.supabase = supabase_client
        self.user_repository = user_repository

    async def signup(self, user_data: UserSignup) -> TokenResponse:
        """Register a new user with authentication and profile creation."""
        try:
            # Authenticate with Supabase Auth
            auth_response = self.supabase.auth.sign_up({
                "email": user_data.email,
                "password": user_data.password,
                "options": {
                    "data": {
                        "full_name": "",
                        "role": settings.reader_role
                    }
                }
            })
            
            if auth_response.user is None:
                raise AuthenticationException(
                    detail="Failed to create user account",
                    error_code="AUTH_SIGNUP_FAILED"
                )

            if auth_response.session is None:
                logger.error(f"No session returned for user {user_data.email}")
                raise AuthenticationException(
                    detail="Authentication session not created. Please check configuration.",
                    error_code="SESSION_CREATION_FAILED"
                )
            
            # Create user profile using repository
            user_create = UserCreate(
                id=auth_response.user.id,
                email=user_data.email,
                full_name="",
                role=settings.reader_role,
                compliance_domains=[],
                is_active=True,
                status="active"
            )
            
            # Create user in database
            try:
                created_user = await self.user_repository.create(user_create)
                logger.info(f"Created user profile for {created_user.email}")
            except Exception as e:
                # If user profile creation fails, we should clean up the auth user
                logger.error(f"Failed to create user profile for {user_data.email}: {e}")
                # Note: In production, you might want to implement auth cleanup here
                raise BusinessLogicException(
                    detail="Failed to create user profile",
                    error_code="USER_PROFILE_CREATION_FAILED",
                    context={"email": user_data.email}
                )
            
            return TokenResponse(
                access_token=auth_response.session.access_token,
                refresh_token=auth_response.session.refresh_token,
                expires_in=auth_response.session.expires_in,
            )
            
        except (AuthenticationException, BusinessLogicException):
            raise
        except Exception as e:
            logger.error(f"Signup failed for {user_data.email}: {e}", exc_info=True)
            if "duplicate key value" in str(e).lower():
                raise ValidationException(
                    detail="User with this email already exists",
                    field="email",
                    value=user_data.email
                )
            raise AuthenticationException(
                detail="Registration failed",
                error_code="SIGNUP_FAILED",
                context={"email": user_data.email}
            )

    async def login(self, login_data: UserLogin) -> TokenResponse:
        """Authenticate user and update login information."""
        try:
            # Authenticate with Supabase Auth
            auth_response = self.supabase.auth.sign_in_with_password({
                "email": login_data.email,
                "password": login_data.password
            })
            
            if auth_response.user is None or auth_response.session is None:
                raise AuthenticationException(
                    detail="Invalid email or password",
                    error_code="INVALID_CREDENTIALS"
                )
            
            # Get user profile using repository
            user = await self.user_repository.get_by_id(auth_response.user.id)
            
            if not user:
                logger.error(f"User profile not found for authenticated user {login_data.email}")
                raise ResourceNotFoundException(
                    resource_type="User",
                    resource_id=auth_response.user.id
                )
            
            # Check if user account is active
            if not user.is_active:
                raise AuthenticationException(
                    detail="User account is deactivated",
                    error_code="ACCOUNT_DEACTIVATED"
                )
            
            return TokenResponse(
                access_token=auth_response.session.access_token,
                refresh_token=auth_response.session.refresh_token,
                expires_in=auth_response.session.expires_in,
            )
            
        except (AuthenticationException, ResourceNotFoundException):
            raise
        except Exception as e:
            logger.error(f"Login failed for {login_data.email}: {e}", exc_info=True)
            raise AuthenticationException(
                detail="Authentication failed",
                error_code="LOGIN_FAILED",
                context={"email": login_data.email}
            )

    async def refresh_token(self, refresh_token_data: RefreshTokenRequest) -> TokenResponse:
        """Refresh user access token."""
        try:
            auth_response = self.supabase.auth.refresh_session(refresh_token_data.refresh_token)
            
            if not auth_response.session:
                raise AuthenticationException(
                    detail="Invalid or expired refresh token",
                    error_code="INVALID_REFRESH_TOKEN"
                )
            
            # Verify user still exists and is active
            if auth_response.user:
                user = await self.user_repository.get_by_id(auth_response.user.id)
                if not user or not user.is_active:
                    raise AuthenticationException(
                        detail="User account is no longer active",
                        error_code="ACCOUNT_INACTIVE"
                    )
            
            return TokenResponse(
                access_token=auth_response.session.access_token,
                refresh_token=auth_response.session.refresh_token,
                expires_in=auth_response.session.expires_in,
            )
            
        except AuthenticationException:
            raise
        except Exception as e:
            logger.error(f"Token refresh failed: {e}", exc_info=True)
            raise AuthenticationException(
                detail="Token refresh failed",
                error_code="TOKEN_REFRESH_FAILED"
            )

    async def logout(self, access_token: str) -> dict:
        """Logout user and invalidate session."""
        try:
            # Sign out from Supabase Auth
            result = self.supabase.auth.sign_out()
            
            return {"message": "Logout successful"}
            
        except Exception as e:
            logger.error(f"Logout failed: {e}", exc_info=True)
            # Don't fail logout completely if there's an error
            return {"message": "Logout completed", "note": "Session may already be invalid"}

# Create service instance (to be used with dependency injection)
def create_auth_service(supabase_client: Client, user_repository: UserRepository) -> AuthService:
    """Factory function to create AuthService instance."""
    return AuthService(supabase_client, user_repository)