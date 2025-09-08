from fastapi import APIRouter, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from auth.decorators import ValidatedUser, authorize
from auth.models import UserSignup, UserLogin, RefreshTokenRequest
from dependencies import AuthServiceDep

# Enhanced error handling imports
from common.exceptions import (
    AuthenticationException,
    AuthorizationException,
    ValidationException,
    InvalidTokenException
)
from common.logging import get_logger, log_security_event, log_business_event
from common.validation import RequestValidator
from common.responses import create_success_response

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = get_logger("auth")

# HTTP bearer security dependency for token extraction
security = HTTPBearer()


@router.post("/signup",
    summary="Register a new user",
    description="Create a new user account with email and password",
    status_code=201
)
async def signup(user_data: UserSignup, request: Request, auth_service: AuthServiceDep):
    """Enhanced signup with comprehensive validation and logging."""
    
    # Enhanced validation
    validator = RequestValidator()
    
    if not validator.validate_required(user_data.email, "email"):
        pass  # Error already added
    elif not validator.validate_email(user_data.email, "email"):
        pass  # Error already added
    
    if not validator.validate_required(user_data.password, "password"):
        pass  # Error already added
    elif not validator.validate_length(user_data.password, "password", min_length=8, max_length=100):
        pass  # Error already added
    
    validator.raise_if_errors()
    
    try:
        # Log signup attempt
        log_security_event(
            event_type="SIGNUP_ATTEMPT",
            ip_address=request.client.host if request.client else None,
            details={"email": user_data.email}
        )
        
        # Call service
        result = await auth_service.signup(user_data)
        
        # Log successful signup (TokenResponse doesn't contain user_id)
        log_business_event(
            event_type="USER_CREATED",
            entity_type="user",
            entity_id="new_user",  # We don't have access to user_id from TokenResponse
            action="create",
            details={"email": user_data.email}
        )
        
        log_security_event(
            event_type="SIGNUP_SUCCESS",
            user_id=None,  # User ID not available in TokenResponse
            ip_address=request.client.host if request.client else None,
            details={"email": user_data.email}
        )
        
        return create_success_response(
            data=result.model_dump(),  # Convert Pydantic model to dict
            meta={"message": "User created successfully"},
            status_code=201
        )
        
    except Exception as e:
        # Log failed signup
        log_security_event(
            event_type="SIGNUP_FAILED",
            ip_address=request.client.host if request.client else None,
            details={"email": user_data.email, "error": str(e)}
        )
        
        if "already exists" in str(e).lower():
            raise ValidationException(
                detail="User with this email already exists",
                field="email",
                value=user_data.email
            )
        
        logger.error(f"Signup failed for {user_data.email}: {e}", exc_info=True)
        raise AuthenticationException(
            detail="Registration failed",
            error_code="SIGNUP_FAILED",
            context={"email": user_data.email}
        )


@router.post("/login",
    summary="Login user",
    description="Authenticate user with email and password"
)
async def login(login_data: UserLogin, request: Request, auth_service: AuthServiceDep):
    """Enhanced login with security logging."""
    
    try:
        # Log login attempt
        log_security_event(
            event_type="LOGIN_ATTEMPT",
            ip_address=request.client.host if request.client else None,
            details={"email": login_data.email}
        )
        
        # Call service
        result = await auth_service.login(login_data)
        
        # Log successful login
        log_security_event(
            event_type="LOGIN_SUCCESS",
            user_id=None,  # User ID not available in TokenResponse
            ip_address=request.client.host if request.client else None,
            details={"email": login_data.email}
        )
        
        return create_success_response(
            data=result.model_dump(),  # Convert Pydantic model to dict
            meta={"message": "Login successful"}
        )
        
    except Exception as e:
        # Log failed login
        log_security_event(
            event_type="LOGIN_FAILED",
            ip_address=request.client.host if request.client else None,
            details={"email": login_data.email, "error": str(e)}
        )
        
        if "invalid credentials" in str(e).lower():
            raise AuthenticationException(
                detail="Invalid email or password",
                error_code="INVALID_CREDENTIALS"
            )
        
        logger.error(f"Login failed for {login_data.email}: {e}", exc_info=True)
        raise AuthenticationException(
            detail="Authentication failed",
            error_code="LOGIN_FAILED"
        )


@router.post("/refresh",
    summary="Refresh access token",
    description="Get a new access token using refresh token"
)
@authorize(check_active=True)
async def refresh_token(refresh_data: RefreshTokenRequest, request: Request, auth_service: AuthServiceDep):
    """Enhanced token refresh with validation."""
    
    try:
        # Validate refresh token format
        if not refresh_data.refresh_token or len(refresh_data.refresh_token) < 10:
            raise InvalidTokenException(
                detail="Invalid refresh token format"
            )
        
        # Call service
        result = await auth_service.refresh_token(refresh_data)
        
        # Log token refresh
        log_security_event(
            event_type="TOKEN_REFRESHED",
            user_id=None,  # User ID not available in TokenResponse
            ip_address=request.client.host if request.client else None
        )
        
        return create_success_response(
            data=result.model_dump(),  # Convert Pydantic model to dict
            meta={"message": "Token refreshed successfully"}
        )
        
    except Exception as e:
        log_security_event(
            event_type="TOKEN_REFRESH_FAILED",
            ip_address=request.client.host if request.client else None,
            details={"error": str(e)}
        )
        
        if "expired" in str(e).lower() or "invalid" in str(e).lower():
            raise InvalidTokenException(
                detail="Refresh token is invalid or expired"
            )
        
        logger.error(f"Token refresh failed: {e}", exc_info=True)
        raise AuthenticationException(
            detail="Token refresh failed",
            error_code="TOKEN_REFRESH_FAILED"
        )


@router.post("/logout",
    summary="Logout user",
    description="Logout user and invalidate tokens"
)
async def logout(
    request: Request,
    auth_service: AuthServiceDep,
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """Enhanced logout with proper token invalidation."""
    
    try:
        # Resolve user via AuthService for logging context
        user_id = None
        try:
            user = await auth_service.get_current_user(credentials.credentials)
            user_id = getattr(user, "id", None)
        except Exception:
            # Continue with logout even if user resolution fails
            pass
        
        # Call service
        result = await auth_service.logout(credentials.credentials)
        
        # Log logout
        log_security_event(
            event_type="LOGOUT_SUCCESS",
            user_id=user_id,
            ip_address=request.client.host if request.client else None
        )
        
        return create_success_response(
            data=result,
            meta={"message": "Logout successful"}
        )
        
    except Exception as e:
        logger.error(f"Logout failed: {e}", exc_info=True)
        # Don't fail logout even if there's an error
        return create_success_response(
            data={"message": "Logout completed"},
            meta={"note": "Token may already be invalid"}
        )


@router.get("/me",
    summary="Get current user profile",
    description="Get the profile of the currently authenticated user"
)
@authorize(allowed_roles=["admin", "compliance_officer", "reader"], check_active=True)
async def get_me(current_user: ValidatedUser = None):
    """Enhanced user profile with additional validation."""
    
    if not current_user:
        raise AuthorizationException(
            detail="User context not available",
            error_code="USER_CONTEXT_MISSING"
        )
    
    if not current_user.is_active:
        raise AuthorizationException(
            detail="Account is deactivated",
            error_code="ACCOUNT_DEACTIVATED"
        )
    
    # Log profile access
    log_business_event(
        event_type="PROFILE_ACCESSED",
        entity_type="user",
        entity_id=current_user.id,
        action="read",
        user_id=current_user.id
    )
    
    profile = {
        "id": current_user.id,
        "email": current_user.email,
        "full_name": getattr(current_user, "full_name", None),
        "role": getattr(current_user, "role", None),
        "compliance_domains": getattr(current_user, "compliance_domains", []),
        "is_active": bool(getattr(current_user, "is_active", False)),
        "created_at": getattr(current_user, "created_at", None),
        "updated_at": getattr(current_user, "updated_at", None),
    }

    return create_success_response(
        data=profile,
        meta={"message": "Profile retrieved successfully"}
    )
