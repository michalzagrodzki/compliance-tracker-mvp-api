import logging
from typing import Optional, List, Dict, Any
from fastapi import Depends, HTTPException
from fastapi_decorators import depends

from services.authentication import AuthenticatedUser, get_current_active_user
from services.user_management import get_user_by_id

logger = logging.getLogger(__name__)

class ValidatedUser(AuthenticatedUser):
    def __init__(self, user_id: str, email: str, user_data: Dict[str, Any]):
        super().__init__(user_id, email, user_data)
        self.full_name = user_data.get("full_name")
        self.role = user_data.get("role")
        self.compliance_domains = user_data.get("compliance_domains", [])
        self.created_at = user_data.get("created_at")
        self.updated_at = user_data.get("updated_at")
        self.is_active = user_data.get("is_active", False)
    
    def has_compliance_access(self, domains: List[str]) -> bool:
        return any(domain in self.compliance_domains for domain in domains)
    
    def has_all_compliance_access(self, domains: List[str]) -> bool:
        return all(domain in self.compliance_domains for domain in domains)
    
    def has_role_access(self, allowed_roles: List[str]) -> bool:
        return self.role in allowed_roles

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
    def my_endpoint(audit_session_id: str, validated_user: ValidatedUser):
        # validated_user is automatically injected and validated
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
    return depends(current_user=Depends(create_dependency()))