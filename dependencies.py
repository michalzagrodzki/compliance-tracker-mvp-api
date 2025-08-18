"""
Dependency injection setup for repositories and services.
"""

from functools import lru_cache
from typing import Annotated
from fastapi import Depends

from db.supabase_client import create_supabase_client
from repositories.user_repository import UserRepository
from services.auth_service import AuthService, create_auth_service
from config.config import settings


@lru_cache()
def get_supabase_client():
    """Get singleton Supabase client."""
    return create_supabase_client()


@lru_cache()
def get_user_repository() -> UserRepository:
    """Get singleton User repository."""
    supabase = get_supabase_client()
    return UserRepository(supabase, settings.supabase_table_users)


@lru_cache()
def get_auth_service() -> AuthService:
    """Get singleton AuthService with dependencies."""
    supabase = get_supabase_client()
    user_repo = get_user_repository()
    return create_auth_service(supabase, user_repo)


# Dependency annotations for FastAPI
SupabaseClient = Annotated[object, Depends(get_supabase_client)]
UserRepositoryDep = Annotated[UserRepository, Depends(get_user_repository)]
AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]