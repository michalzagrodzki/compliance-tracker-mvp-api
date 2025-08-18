"""
User entity model for the domain layer.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, EmailStr, Field
from enum import Enum


class UserRole(str, Enum):
    """User roles enumeration."""
    ADMIN = "admin"
    COMPLIANCE_OFFICER = "compliance_officer"
    READER = "reader"


class UserStatus(str, Enum):
    """User status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING = "pending"


class User(BaseModel):
    """
    User entity representing a user in the system.
    """
    id: str
    email: EmailStr
    full_name: str = ""
    role: UserRole = UserRole.READER
    compliance_domains: List[str] = Field(default_factory=list)
    is_active: bool = True
    status: UserStatus = UserStatus.ACTIVE
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    login_count: int = 0

    class Config:
        # Allow conversion from dict
        from_attributes = True
        # Use enum values for serialization
        use_enum_values = True

    def has_compliance_access(self, domains: List[str]) -> bool:
        """Check if user has access to any of the specified compliance domains."""
        return any(domain in self.compliance_domains for domain in domains)

    def has_all_compliance_access(self, domains: List[str]) -> bool:
        """Check if user has access to all specified compliance domains."""
        return all(domain in self.compliance_domains for domain in domains)

    def has_role_access(self, allowed_roles: List[str]) -> bool:
        """Check if user's role is in the list of allowed roles."""
        return self.role.value in allowed_roles

    def is_admin(self) -> bool:
        """Check if user has admin role."""
        return self.role == UserRole.ADMIN

    def is_compliance_officer(self) -> bool:
        """Check if user has compliance officer role."""
        return self.role == UserRole.COMPLIANCE_OFFICER

    def can_access_domain(self, domain: str) -> bool:
        """Check if user can access a specific compliance domain."""
        return domain in self.compliance_domains

    def update_login_info(self) -> None:
        """Update login information when user logs in."""
        self.last_login = datetime.utcnow()
        self.login_count += 1
        self.updated_at = datetime.utcnow()

    def activate(self) -> None:
        """Activate the user account."""
        self.is_active = True
        self.status = UserStatus.ACTIVE
        self.updated_at = datetime.utcnow()

    def deactivate(self) -> None:
        """Deactivate the user account."""
        self.is_active = False
        self.status = UserStatus.INACTIVE
        self.updated_at = datetime.utcnow()

    def suspend(self) -> None:
        """Suspend the user account."""
        self.is_active = False
        self.status = UserStatus.SUSPENDED
        self.updated_at = datetime.utcnow()

    def add_compliance_domain(self, domain: str) -> None:
        """Add a compliance domain to the user."""
        if domain not in self.compliance_domains:
            self.compliance_domains.append(domain)
            self.updated_at = datetime.utcnow()

    def remove_compliance_domain(self, domain: str) -> None:
        """Remove a compliance domain from the user."""
        if domain in self.compliance_domains:
            self.compliance_domains.remove(domain)
            self.updated_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary for database storage."""
        data = self.model_dump()
        # Ensure datetime fields are in ISO format
        data["created_at"] = self.created_at.isoformat() if self.created_at else None
        data["updated_at"] = self.updated_at.isoformat() if self.updated_at else None
        data["last_login"] = self.last_login.isoformat() if self.last_login else None
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        """Create user from dictionary data."""
        # Parse datetime strings
        if isinstance(data.get("created_at"), str):
            data["created_at"] = datetime.fromisoformat(data["created_at"].replace('Z', '+00:00'))
        if isinstance(data.get("updated_at"), str):
            data["updated_at"] = datetime.fromisoformat(data["updated_at"].replace('Z', '+00:00'))
        if data.get("last_login") and isinstance(data["last_login"], str):
            data["last_login"] = datetime.fromisoformat(data["last_login"].replace('Z', '+00:00'))
        
        return cls(**data)


class UserCreate(BaseModel):
    """Model for creating a new user."""
    id: str  # Will come from Supabase auth
    email: EmailStr
    full_name: str = ""
    role: UserRole = UserRole.READER
    compliance_domains: List[str] = Field(default_factory=list)
    is_active: bool = True
    status: UserStatus = UserStatus.ACTIVE


class UserUpdate(BaseModel):
    """Model for updating user information."""
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    compliance_domains: Optional[List[str]] = None
    is_active: Optional[bool] = None
    status: Optional[UserStatus] = None

    class Config:
        use_enum_values = True


class UserFilter(BaseModel):
    """Model for filtering users."""
    email: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    status: Optional[UserStatus] = None
    compliance_domains: Optional[List[str]] = None

    class Config:
        use_enum_values = True