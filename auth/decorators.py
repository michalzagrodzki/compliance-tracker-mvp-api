from functools import wraps
import inspect
import logging
from typing import Optional, List
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.models import AuthenticatedUser, ValidatedUser
from dependencies import AuthServiceDep

logger = logging.getLogger(__name__)
security = HTTPBearer()

async def get_current_active_user(
    auth_service: AuthServiceDep,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> AuthenticatedUser:
    user = await auth_service.get_current_user(credentials.credentials)
    return AuthenticatedUser(user.id, user.email, user.model_dump())

def authorize(
    domains: Optional[List[str]] = None,
    allowed_roles: Optional[List[str]] = None,
    require_all_domains: bool = False,
    check_active: bool = True
):
    """
    Authorization decorator using fastapi-decorators pattern.
    
    Usage:
    @authorize(domains=["ISO27001"], allowed_roles=["admin"])
    def my_endpoint(audit_session_id: str, current_user: ValidatedUser):
        # current_user is automatically injected and validated
        pass
    """
    def create_dependency():
        def auth_dependency(
            current_user: AuthenticatedUser = Depends(get_current_active_user)
        ) -> ValidatedUser:
            try:
                # Use data from the authenticated user resolved via AuthService
                user_data = current_user.user_data

                if check_active and not user_data.get("is_active", False):
                    logger.warning(f"Inactive user blocked: {user_data.get('email')}")
                    raise HTTPException(
                        status_code=403,
                        detail="Your account has been deactivated. Please contact support."
                    )

                user_role = user_data.get("role")
                logger.warning(f"Role validation: user_role='{user_role}', required={allowed_roles}")
                
                if allowed_roles and user_role not in allowed_roles:
                    logger.warning(f"ROLE ACCESS DENIED: '{user_role}' not in {allowed_roles}")
                    raise HTTPException(
                        status_code=403,
                        detail=f"Access denied."
                    )

                if domains:
                    user_domains = user_data.get("compliance_domains", [])
                    logger.warning(f"Domain validation: user_domains={user_domains}, required={domains}")
                    
                    if require_all_domains:
                        missing = [d for d in domains if d not in user_domains]
                        if missing:
                            logger.warning(f"DOMAIN ACCESS DENIED: missing {missing}")
                            raise HTTPException(
                                status_code=403,
                                detail=f"Access denied"
                            )
                    else:
                        if not any(d in user_domains for d in domains):
                            logger.warning(f"DOMAIN ACCESS DENIED: no access to any of {domains}")
                            raise HTTPException(
                                status_code=403,
                                detail=f"Access denied"
                            )
                
                logger.warning(f"AUTHORIZATION SUCCESSFUL for {user_data.get('email')}")
                return ValidatedUser(current_user.id, current_user.email, user_data)
                
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Authorization error: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail="Authorization failed")
        
        return auth_dependency
    def decorator(func):
        sig = inspect.signature(func)
        expects_current_user = 'current_user' in sig.parameters

        # Prepare dependency once
        dependency = Depends(create_dependency())

        if expects_current_user:
            # Expose `current_user` as a FastAPI dependency parameter
            @wraps(func)
            async def wrapper(*args, current_user: ValidatedUser = dependency, **kwargs):
                if inspect.iscoroutinefunction(func):
                    return await func(*args, current_user=current_user, **kwargs)
                else:
                    return func(*args, current_user=current_user, **kwargs)

            # Replace only the `current_user` parameter to be a dependency
            new_params = []
            for name, p in sig.parameters.items():
                if name == 'current_user':
                    p = p.replace(default=dependency, annotation=ValidatedUser)
                new_params.append(p)
            wrapper.__signature__ = sig.replace(parameters=tuple(new_params))
            return wrapper
        else:
            # Inject dependency without exposing it as a real request parameter
            @wraps(func)
            async def wrapper(*args, _validated_user: ValidatedUser = dependency, **kwargs):
                if inspect.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)

            # Add a hidden keyword-only dependency parameter to the signature
            params = list(sig.parameters.values())
            # Insert before **kwargs if present, otherwise append
            var_kw_index = next((i for i, p in enumerate(params) if p.kind == inspect.Parameter.VAR_KEYWORD), None)
            hidden_param = inspect.Parameter(
                name="_validated_user",
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=dependency,
                annotation=ValidatedUser,
            )
            if var_kw_index is not None:
                params.insert(var_kw_index, hidden_param)
            else:
                params.append(hidden_param)
            wrapper.__signature__ = sig.replace(parameters=tuple(params))
            return wrapper
    
    return decorator
