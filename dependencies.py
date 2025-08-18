"""
Dependency injection setup for repositories and services.
"""

from functools import lru_cache
from typing import Annotated
from fastapi import Depends

from db.supabase_client import create_supabase_client
from repositories.user_repository import UserRepository
from repositories.compliance_gap_repository import ComplianceGapRepository
from services.auth_service import AuthService, create_auth_service
from services.compliance_gap_service import ComplianceGapService, create_compliance_gap_service
from services.ai_service import AIService, create_ai_service
from services.compliance_recommendation_service import ComplianceRecommendationService, create_compliance_recommendation_service
from adapters.openai_adapter import OpenAIAdapter, MockAIAdapter
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
def get_compliance_gap_repository() -> ComplianceGapRepository:
    """Get singleton ComplianceGap repository."""
    supabase = get_supabase_client()
    return ComplianceGapRepository(supabase, settings.supabase_table_compliance_gaps)


@lru_cache()
def get_auth_service() -> AuthService:
    """Get singleton AuthService with dependencies."""
    supabase = get_supabase_client()
    user_repo = get_user_repository()
    return create_auth_service(supabase, user_repo)


@lru_cache()
def get_compliance_gap_service() -> ComplianceGapService:
    """Get singleton ComplianceGapService with dependencies."""
    gap_repo = get_compliance_gap_repository()
    user_repo = get_user_repository()
    return create_compliance_gap_service(gap_repo, user_repo)


@lru_cache()
def get_ai_adapter():
    """Get AI adapter (OpenAI or Mock based on configuration)."""
    # Check if we have OpenAI API key
    openai_api_key = getattr(settings, 'openai_api_key', None)
    
    if openai_api_key:
        return OpenAIAdapter(api_key=openai_api_key)
    else:
        # Fall back to mock adapter for development/testing
        return MockAIAdapter(delay_ms=500)


@lru_cache()
def get_ai_service() -> AIService:
    """Get singleton AIService with dependencies."""
    ai_adapter = get_ai_adapter()
    return create_ai_service(ai_adapter, enable_cache=True)


@lru_cache()
def get_compliance_recommendation_service() -> ComplianceRecommendationService:
    """Get singleton ComplianceRecommendationService with dependencies."""
    ai_service = get_ai_service()
    gap_repo = get_compliance_gap_repository()
    user_repo = get_user_repository()
    return create_compliance_recommendation_service(ai_service, gap_repo, user_repo)


# Dependency annotations for FastAPI
SupabaseClient = Annotated[object, Depends(get_supabase_client)]
UserRepositoryDep = Annotated[UserRepository, Depends(get_user_repository)]
ComplianceGapRepositoryDep = Annotated[ComplianceGapRepository, Depends(get_compliance_gap_repository)]
AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]
ComplianceGapServiceDep = Annotated[ComplianceGapService, Depends(get_compliance_gap_service)]
AIServiceDep = Annotated[AIService, Depends(get_ai_service)]
ComplianceRecommendationServiceDep = Annotated[ComplianceRecommendationService, Depends(get_compliance_recommendation_service)]