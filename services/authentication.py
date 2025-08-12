import logging
from typing import Optional, Dict, List
from fastapi import HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from supabase import Client
from auth.decorators import ValidatedUser
from auth.models import RefreshTokenRequest, TokenResponse, UserLogin, UserResponse, UserSignup
from db.supabase_client import create_supabase_client
from config.config import settings
from config.config import settings

logger = logging.getLogger(__name__)

security = HTTPBearer()

class AuthService:
    def __init__(self):
        self.supabase: Client = create_supabase_client()
    
    def signup(self, user_data: UserSignup) -> TokenResponse:
        try:
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
                raise HTTPException(
                    status_code=400,
                    detail="Failed to create user account"
                )

            if auth_response.session is None:
                logger.error(f"No session returned for user {user_data.email} despite email confirmation being disabled")
                raise HTTPException(
                    status_code=500,
                    detail="Authentication session not created. Please check Supabase configuration."
                )
            
            user_profile = {
                "id": auth_response.user.id,
                "email": user_data.email,
                "full_name": "",
                "role": settings.reader_role,
                "compliance_domains": [],
                "is_active": True
            }
            
            users_response = self.supabase.table(settings.supabase_table_users).insert(user_profile).execute()
            
            if not users_response.data:
                logger.error("Failed to create user profile")
                raise HTTPException(
                    status_code=500,
                    detail="Failed to create user profile"
                )
            
            return TokenResponse(
                access_token=auth_response.session.access_token,
                refresh_token=auth_response.session.refresh_token,
                expires_in=auth_response.session.expires_in,
            )
            
        except Exception as e:
            logger.error(f"Signup failed: {e}")
            if "duplicate key value" in str(e).lower():
                raise HTTPException(
                    status_code=400,
                    detail="User with this email already exists"
                )
            raise HTTPException(
                status_code=500,
                detail=f"Registration failed: {str(e)}"
            )
    
    def login(self, login_data: UserLogin) -> TokenResponse:
        try:
            auth_response = self.supabase.auth.sign_in_with_password({
                "email": login_data.email,
                "password": login_data.password
            })
            
            if auth_response.user is None or auth_response.session is None:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid email or password"
                )
            
            user_response = self.supabase.table(settings.supabase_table_users).select("*").eq("id", auth_response.user.id).execute()
            
            if not user_response.data:
                raise HTTPException(
                    status_code=404,
                    detail="User profile not found"
                )
            
            user_record = user_response.data[0]
            
            if not user_record.get("is_active", True):
                raise HTTPException(
                    status_code=403,
                    detail="User account is deactivated"
                )
            
            return TokenResponse(
                access_token=auth_response.session.access_token,
                refresh_token=auth_response.session.refresh_token,
                expires_in=auth_response.session.expires_in,
            )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Login failed: {e}")
            raise HTTPException(
                status_code=401,
                detail="Authentication failed"
            )
    
    def refresh_token(self, refresh_token_data: RefreshTokenRequest) -> TokenResponse:
        try:
            auth_response = self.supabase.auth.refresh_session(refresh_token_data.refresh_token)
            
            if auth_response.user is None or auth_response.session is None:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid refresh token"
                )
            
            user_response = self.supabase.table(settings.supabase_table_users).select("*").eq("id", auth_response.user.id).execute()
            
            if not user_response.data:
                raise HTTPException(
                    status_code=404,
                    detail="User profile not found"
                )
            
            user_record = user_response.data[0]
            
            return TokenResponse(
                access_token=auth_response.session.access_token,
                refresh_token=auth_response.session.refresh_token,
                expires_in=auth_response.session.expires_in,
            )
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise HTTPException(
                status_code=401,
                detail="Token refresh failed"
            )
    
    def logout(self, token: str) -> Dict[str, str]:
        try:
            self.supabase.auth.set_session(token, "")
            self.supabase.auth.sign_out()
            
            return {"message": "Successfully logged out"}
            
        except Exception as e:
            logger.error(f"Logout failed: {e}")
            return {"message": "Logged out (with warnings)"}
    
    def get_current_user(self, token: str) -> UserResponse:
        try:
            user_response = self.supabase.auth.get_user(token)
            
            if user_response.user is None:
                raise HTTPException(
                    status_code=401,
                    detail="Invalid or expired token"
                )
            
            profile_response = self.supabase.table(settings.supabase_table_users).select("*").eq("id", user_response.user.id).execute()
            
            if not profile_response.data:
                raise HTTPException(
                    status_code=404,
                    detail="User profile not found"
                )
            
            user_record = profile_response.data[0]
            
            if not user_record.get("is_active", True):
                raise HTTPException(
                    status_code=403,
                    detail="User account is deactivated"
                )
            
            return UserResponse(**user_record)
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Get current user failed: {e}")
            raise HTTPException(
                status_code=401,
                detail="Authentication failed"
            )

auth_service = AuthService()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> UserResponse:
    return auth_service.get_current_user(credentials.credentials)

def get_current_active_user(current_user: UserResponse = Depends(get_current_user)) -> UserResponse:
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user

def require_admin(current_user: UserResponse = Depends(get_current_active_user)) -> UserResponse:
    if not settings.is_admin_role(current_user.role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user

def require_compliance_officer_or_admin(current_user: UserResponse = Depends(get_current_active_user)) -> UserResponse:
    if not settings.has_elevated_permissions(current_user.role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compliance officer or admin access required"
        )
    return current_user

def require_compliance_domain_access(domain: str):
    def check_domain_access(current_user: UserResponse = Depends(get_current_active_user)) -> UserResponse:
        if settings.is_admin_role(current_user.role):
            return current_user  # Admins have access to all domains
        
        if domain not in current_user.compliance_domains:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied to compliance domain: {domain}"
            )
        return current_user
    
    return check_domain_access

def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))) -> Optional[UserResponse]:
    if credentials is None:
        return None
    
    try:
        return auth_service.get_current_user(credentials.credentials)
    except HTTPException:
        return None

def _extract_access_token(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    for name in ("access_token", "Authorization", "auth_token", "token"):
        if name in request.cookies:
            return request.cookies[name]
    return None

def authenticate_and_authorize(
    request: Request,
    allowed_roles: Optional[List[str]] = None,
    domains: Optional[List[str]] = None,
    check_active: bool = True,
) -> ValidatedUser:
    """
    - Extracts token from headers/cookies
    - Uses your AuthService to resolve the user (reuses Supabase)
    - Applies the same checks as your @authorize decorator
    - Returns a ValidatedUser-like object for downstream code
    """
    token = _extract_access_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization token")

    user = auth_service.get_current_user(token)

    if check_active and not getattr(user, "is_active", True):
        raise HTTPException(status_code=403, detail="Your account has been deactivated. Please contact support.")

    if allowed_roles and getattr(user, "role", None) not in allowed_roles:
        raise HTTPException(status_code=403, detail="Access denied.")

    if domains:
        user_domains = getattr(user, "compliance_domains", []) or []
        if not any(d in user_domains for d in domains):
            raise HTTPException(status_code=403, detail="Access denied.")

    try:
        data = user.model_dump() if hasattr(user, "model_dump") else dict(user)
    except Exception:
        data = {
            "id": getattr(user, "id", None),
            "email": getattr(user, "email", None),
            "role": getattr(user, "role", None),
            "compliance_domains": getattr(user, "compliance_domains", []) or [],
            "is_active": getattr(user, "is_active", True),
        }

    if "role" in data and "compliance_domains" in data:
        try:
            return ValidatedUser(
                id=data.get("id"),
                email=data.get("email"),
                user_data=data 
            )
        except TypeError:
            return ValidatedUser(
                id=data.get("id"),
                email=data.get("email"),
                role=data.get("role"),
                compliance_domains=data.get("compliance_domains") or [],
                is_active=data.get("is_active", True),
            )
    else:
        raise HTTPException(status_code=500, detail="Authorization failed")