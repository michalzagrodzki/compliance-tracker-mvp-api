from functools import wraps
import inspect
import logging
from typing import Optional, List
from fastapi import Depends, HTTPException
from fastapi_decorators import depends
from auth.models import AuthenticatedUser, ValidatedUser
from services.authentication import get_current_active_user
from services.user_management import get_user_by_id

logger = logging.getLogger(__name__)

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
                user_data = get_user_by_id(current_user.id)

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
        
        if expects_current_user:
            return depends(current_user=Depends(create_dependency()))(func)
        else:
            dependency = Depends(create_dependency())
            
            @wraps(func)
            async def wrapper(*args, validated_user: ValidatedUser = dependency, **kwargs):    
                return await func(*args, **kwargs) if inspect.iscoroutinefunction(func) else func(*args, **kwargs)
            
            new_params = [p for name, p in sig.parameters.items()]
            wrapper.__signature__ = sig.replace(parameters=new_params)
            
            return wrapper
    
    return decorator