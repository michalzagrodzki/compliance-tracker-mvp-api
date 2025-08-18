"""
Example usage of the Repository pattern with User domain.
This shows how to use the new repository-based architecture.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from typing import List

# Repository and entity imports
from entities.user import User, UserCreate, UserUpdate, UserFilter, UserRole
from repositories.user_repository import UserRepository
from services.auth_service import AuthService
from dependencies import get_supabase_client, get_user_repository, get_auth_service


async def repository_examples():
    """Examples of using the User repository directly."""
    
    # Get repository instance
    user_repo = get_user_repository()
    
    print("=== Repository Pattern Examples ===\n")
    
    # 1. Create a new user (simulating what happens after Supabase Auth)
    print("1. Creating a new user...")
    try:
        new_user = UserCreate(
            id="test-user-123",  # Would come from Supabase Auth
            email="test@example.com",
            full_name="Test User",
            role=UserRole.READER,
            compliance_domains=["GDPR", "ISO27001"],
            is_active=True
        )
        
        created_user = await user_repo.create(new_user)
        print(f"✅ Created user: {created_user.email} (ID: {created_user.id})")
        
    except Exception as e:
        print(f"❌ Failed to create user: {e}")
    
    # 2. Get user by ID
    print("\n2. Retrieving user by ID...")
    try:
        user = await user_repo.get_by_id("test-user-123")
        if user:
            print(f"✅ Found user: {user.email}, Role: {user.role.value}")
        else:
            print("❌ User not found")
    except Exception as e:
        print(f"❌ Failed to get user: {e}")
    
    # 3. Update user
    print("\n3. Updating user...")
    try:
        update_data = UserUpdate(
            full_name="Updated Test User",
            role=UserRole.COMPLIANCE_OFFICER
        )
        
        updated_user = await user_repo.update("test-user-123", update_data)
        if updated_user:
            print(f"✅ Updated user: {updated_user.full_name}, New role: {updated_user.role.value}")
    except Exception as e:
        print(f"❌ Failed to update user: {e}")
    
    # 4. List users with filters
    print("\n4. Listing active users...")
    try:
        filters = UserFilter(is_active=True)
        users = await user_repo.list(limit=10, filters=filters)
        print(f"✅ Found {len(users)} active users")
        
        for user in users[:3]:  # Show first 3
            print(f"   - {user.email} ({user.role.value})")
            
    except Exception as e:
        print(f"❌ Failed to list users: {e}")
    
    # 5. Get users by compliance domain
    print("\n5. Getting users with GDPR access...")
    try:
        gdpr_users = await user_repo.get_by_compliance_domain("GDPR")
        print(f"✅ Found {len(gdpr_users)} users with GDPR access")
        
    except Exception as e:
        print(f"❌ Failed to get GDPR users: {e}")
    
    # 6. Soft delete user
    print("\n6. Soft deleting user...")
    try:
        deleted = await user_repo.delete("test-user-123")
        if deleted:
            print("✅ User soft deleted (deactivated)")
        
    except Exception as e:
        print(f"❌ Failed to delete user: {e}")


async def service_examples():
    """Examples of using the AuthService with repository pattern."""
    
    print("\n=== Service Layer Examples ===\n")
    
    # Get service instance
    auth_service = get_auth_service()
    
    # 1. Get user profile using service
    print("1. Getting user profile via service...")
    try:
        user_profile = await auth_service.get_user_profile("some-user-id")
        if user_profile:
            print(f"✅ Found profile: {user_profile.email}")
        else:
            print("❌ Profile not found")
            
    except Exception as e:
        print(f"❌ Service error: {e}")
    
    # 2. Update user profile using service
    print("\n2. Updating profile via service...")
    try:
        update_data = {
            "full_name": "Service Updated Name",
            "compliance_domains": ["GDPR", "ISO27001", "SOC2"]
        }
        
        updated_profile = await auth_service.update_user_profile("some-user-id", update_data)
        if updated_profile:
            print(f"✅ Updated profile: {updated_profile.full_name}")
            print(f"   Domains: {updated_profile.compliance_domains}")
            
    except Exception as e:
        print(f"❌ Service update error: {e}")


def show_entity_features():
    """Demonstrate entity model features."""
    
    print("\n=== Entity Model Features ===\n")
    
    # Create a user entity
    from datetime import datetime
    
    user_data = {
        "id": "demo-user",
        "email": "demo@example.com",
        "full_name": "Demo User",
        "role": "compliance_officer",
        "compliance_domains": ["GDPR", "ISO27001"],
        "is_active": True,
        "status": "active",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "login_count": 5
    }
    
    user = User.from_dict(user_data)
    
    print("1. User entity created:")
    print(f"   Email: {user.email}")
    print(f"   Role: {user.role.value}")
    print(f"   Domains: {user.compliance_domains}")
    
    print("\n2. Testing domain access methods:")
    print(f"   Can access GDPR: {user.can_access_domain('GDPR')}")
    print(f"   Can access SOC2: {user.can_access_domain('SOC2')}")
    print(f"   Has all access [GDPR, ISO27001]: {user.has_all_compliance_access(['GDPR', 'ISO27001'])}")
    
    print("\n3. Testing role methods:")
    print(f"   Is admin: {user.is_admin()}")
    print(f"   Is compliance officer: {user.is_compliance_officer()}")
    print(f"   Can access admin endpoints: {user.has_role_access(['admin'])}")
    
    print("\n4. Updating user state:")
    user.update_login_info()
    print(f"   Login count after update: {user.login_count}")
    print(f"   Last login updated: {user.last_login is not None}")
    
    user.add_compliance_domain("SOC2")
    print(f"   Domains after adding SOC2: {user.compliance_domains}")


async def main():
    """Run all examples."""
    print("🚀 Repository Pattern Implementation - Authentication Domain\n")
    
    # Show entity features (doesn't require DB)
    show_entity_features()
    
    # Repository and service examples (require DB connection)
    try:
        await repository_examples()
        await service_examples()
        
    except Exception as e:
        print(f"\n❌ Database connection error: {e}")
        print("💡 Make sure your Supabase connection is configured correctly")
    
    print("\n✨ Repository Pattern Examples Complete!")


if __name__ == "__main__":
    asyncio.run(main())