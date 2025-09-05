from datetime import datetime
from typing import Any, Dict, List
from pydantic import BaseModel, EmailStr

class AuthenticatedUser:
    def __init__(self, id: str, email: str, user_data: Dict[str, Any]):
        self.id = id
        self.email = email
        self.user_data = user_data
        self.is_active = user_data.get("is_active", True)
    
    def __str__(self):
        return f"User(id={self.user_id}, email={self.email})"

class ValidatedUser(AuthenticatedUser):
    def __init__(self, id: str, email: str, user_data: Dict[str, Any]):
        super().__init__(id, email, user_data)
        self.full_name = user_data.get("full_name")
        self.role = user_data.get("role")
        self.compliance_domains = user_data.get("compliance_domains", [])
        self.created_at = user_data.get("created_at")
        self.updated_at = user_data.get("updated_at")
        self.is_active = user_data.get("is_active", False)

class UserSignup(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    compliance_domains: List[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class RefreshTokenRequest(BaseModel):
    refresh_token: str