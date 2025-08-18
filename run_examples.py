#!/usr/bin/env python3
"""
Runner script for all usage examples.
This script helps you run the repository pattern examples easily.
"""

import sys
import os
import asyncio
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def print_banner(title: str):
    """Print a nice banner for each example."""
    print("\n" + "="*60)
    print(f"  {title}")
    print("="*60 + "\n")

def print_menu():
    """Print the example selection menu."""
    print("🚀 Repository Pattern Usage Examples")
    print("\nAvailable examples:")
    print("1. User Repository Pattern (entities + repositories)")
    print("2. ComplianceGap Repository Pattern (full CRUD + business logic)")  
    print("3. AI Services Architecture (adapters + services + caching)")
    print("4. Run all examples")
    print("5. Exit")
    print("\nNote: Examples 1-3 will show entity features even without database.")
    print("Database examples will show connection errors if Supabase isn't configured.")

def run_entity_examples_only():
    """Run only entity model examples (no database required)."""
    print_banner("Entity Model Examples (No Database Required)")
    
    # User entity example
    print("🧑‍💼 User Entity Features:")
    try:
        from entities.user import User, UserRole, UserStatus
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
        print(f"✅ User created: {user.email}")
        print(f"   Role: {user.role.value}")
        print(f"   Domains: {user.compliance_domains}")
        print(f"   Can access GDPR: {user.can_access_domain('GDPR')}")
        print(f"   Is compliance officer: {user.is_compliance_officer()}")
        
    except Exception as e:
        print(f"❌ User entity example failed: {e}")
    
    # ComplianceGap entity example  
    print("\n📋 ComplianceGap Entity Features:")
    try:
        from entities.compliance_gap import ComplianceGap, GapType, RiskLevel
        from datetime import datetime
        
        gap_data = {
            "id": "demo-gap",
            "user_id": "user-123",
            "audit_session_id": "audit-456", 
            "compliance_domain": "GDPR",
            "gap_type": "missing_policy",
            "gap_category": "Data Processing",
            "gap_title": "Missing Data Retention Policy",
            "gap_description": "No clear data retention policy found",
            "original_question": "What is our data retention policy?",
            "risk_level": "high",
            "business_impact": "medium", 
            "status": "identified",
            "regulatory_requirement": True,
            "detected_at": datetime.utcnow(),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        gap = ComplianceGap.from_dict(gap_data)
        print(f"✅ Gap created: {gap.gap_title}")
        print(f"   Risk: {gap.risk_level.value}")
        print(f"   Is critical: {gap.is_critical()}")
        print(f"   Is regulatory: {gap.is_regulatory()}")
        print(f"   Age: {gap.get_age_in_days()} days")
        
        # Test business methods
        gap.acknowledge("compliance-officer")
        print(f"   Status after acknowledge: {gap.status.value}")
        
    except Exception as e:
        print(f"❌ ComplianceGap entity example failed: {e}")
    
    print("\n✨ Entity examples completed successfully!")
    print("💡 These examples work without any database configuration.")

async def run_example(example_num: int):
    """Run a specific example."""
    
    if example_num == 1:
        print_banner("User Repository Pattern Example")
        try:
            # Import and run the user repository example
            from examples.repository_usage import main as user_main
            await user_main()
        except Exception as e:
            print(f"❌ User repository example failed: {e}")
            print("💡 This requires Supabase database configuration")
            run_entity_examples_only()
    
    elif example_num == 2:
        print_banner("ComplianceGap Repository Pattern Example") 
        try:
            # Import and run the compliance gap example
            from examples.compliance_gap_usage import main as gap_main
            await gap_main()
        except Exception as e:
            print(f"❌ ComplianceGap repository example failed: {e}")
            print("💡 This requires Supabase database configuration")
            run_entity_examples_only()
    
    elif example_num == 3:
        print_banner("AI Services Architecture Example")
        try:
            # Import and run the AI services example
            from examples.ai_services_usage import main as ai_main
            await ai_main()
        except Exception as e:
            print(f"❌ AI services example failed: {e}")
            print("💡 AI services use mock adapter by default, so this should work")
    
    elif example_num == 4:
        print_banner("Running All Examples")
        for i in range(1, 4):
            await run_example(i)
            print("\n" + "-"*40 + "\n")

async def main():
    """Main runner function."""
    
    while True:
        print_menu()
        
        try:
            choice = input("\nSelect an example (1-5): ").strip()
            
            if choice == '5':
                print("\n👋 Goodbye!")
                break
            elif choice in ['1', '2', '3', '4']:
                await run_example(int(choice))
            else:
                print("❌ Invalid choice. Please select 1-5.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    asyncio.run(main())