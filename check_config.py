#!/usr/bin/env python3
"""
Configuration checker for repository pattern examples.
This script checks if your environment is properly configured.
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def check_imports():
    """Check if all required modules can be imported."""
    print("🔍 Checking module imports...")
    
    modules_to_check = [
        ("entities.user", "User entity"),
        ("entities.compliance_gap", "ComplianceGap entity"),
        ("repositories.base", "Base repository"),
        ("repositories.user_repository", "User repository"),
        ("repositories.compliance_gap_repository", "ComplianceGap repository"),
        ("services.ai_service", "AI service"),
        ("adapters.openai_adapter", "OpenAI adapter"),
        ("dependencies", "Dependency injection"),
        ("common.exceptions", "Custom exceptions"),
        ("common.logging", "Logging utilities"),
    ]
    
    all_good = True
    for module_name, description in modules_to_check:
        try:
            __import__(module_name)
            print(f"✅ {description}: OK")
        except ImportError as e:
            print(f"❌ {description}: FAILED - {e}")
            all_good = False
        except Exception as e:
            print(f"⚠️ {description}: WARNING - {e}")
    
    return all_good

def check_dependencies():
    """Check if required dependencies are installed."""
    print("\n📦 Checking Python dependencies...")
    
    dependencies = [
        ("pydantic", "Data validation and serialization"),
        ("fastapi", "Web framework"),
        ("supabase", "Database client"),
        ("asyncio", "Async/await support"),
        ("uuid", "UUID generation"),
        ("datetime", "Date/time handling"),
        ("decimal", "Decimal number handling"),
        ("typing", "Type hints"),
        ("enum", "Enumerations"),
        ("dataclasses", "Data classes"),
    ]
    
    all_good = True
    for dep_name, description in dependencies:
        try:
            __import__(dep_name)
            print(f"✅ {dep_name}: OK")
        except ImportError:
            print(f"❌ {dep_name}: MISSING - {description}")
            all_good = False
    
    return all_good

def check_configuration():
    """Check if configuration is properly set up."""
    print("\n⚙️ Checking configuration...")
    
    try:
        from config.config import settings
        print(f"✅ Settings loaded: OK")
        
        # Check for important settings
        if hasattr(settings, 'supabase_table_users'):
            print(f"✅ User table configured: {settings.supabase_table_users}")
        else:
            print(f"⚠️ User table not configured")
        
        if hasattr(settings, 'supabase_table_compliance_gaps'):
            print(f"✅ Compliance gaps table configured: {settings.supabase_table_compliance_gaps}")
        else:
            print(f"⚠️ Compliance gaps table not configured")
            
        if hasattr(settings, 'openai_api_key') and settings.openai_api_key:
            print(f"✅ OpenAI API key: Configured")
        else:
            print(f"⚠️ OpenAI API key: Not configured (will use mock adapter)")
            
    except Exception as e:
        print(f"❌ Configuration check failed: {e}")
        return False
    
    return True

def check_database_connection():
    """Check if database connection works."""
    print("\n🗄️ Checking database connection...")
    
    try:
        from db.supabase_client import create_supabase_client
        supabase = create_supabase_client()
        print(f"✅ Supabase client created: OK")
        
        # Try a simple query (this might fail if not configured)
        try:
            # This is just a connection test, not a real query
            if hasattr(supabase, 'url') and supabase.url:
                print(f"✅ Supabase URL configured: OK")
            else:
                print(f"⚠️ Supabase URL not properly configured")
        except Exception as e:
            print(f"⚠️ Database connection test warning: {e}")
        
    except Exception as e:
        print(f"❌ Database connection check failed: {e}")
        print(f"💡 This is expected if Supabase environment variables are not set")
        return False
    
    return True

def show_environment_setup():
    """Show environment setup instructions."""
    print("\n📋 Environment Setup Instructions:")
    print("\n1. **Required Environment Variables:**")
    print("   - SUPABASE_URL: Your Supabase project URL")
    print("   - SUPABASE_ANON_KEY: Your Supabase anonymous key")
    print("   - OPENAI_API_KEY: Your OpenAI API key (optional, uses mock if not set)")
    print("\n2. **Database Tables Required:**")
    print("   - users: User profiles and authentication")
    print("   - compliance_gaps: Compliance gap records")
    print("\n3. **Python Dependencies:**")
    print("   pip install fastapi supabase pydantic openai")
    print("\n4. **Running Examples:**")
    print("   python3 run_examples.py")
    print("   python3 examples/repository_usage.py")
    print("   python3 examples/compliance_gap_usage.py")
    print("   python3 examples/ai_services_usage.py")

def main():
    """Main configuration checker."""
    print("🔧 Repository Pattern Configuration Checker")
    print("="*50)
    
    # Check all components
    imports_ok = check_imports()
    deps_ok = check_dependencies()
    config_ok = check_configuration()
    db_ok = check_database_connection()
    
    print("\n📊 Summary:")
    print(f"   Imports: {'✅ OK' if imports_ok else '❌ Issues'}")
    print(f"   Dependencies: {'✅ OK' if deps_ok else '❌ Issues'}")
    print(f"   Configuration: {'✅ OK' if config_ok else '❌ Issues'}")
    print(f"   Database: {'✅ OK' if db_ok else '⚠️ Not configured'}")
    
    if imports_ok and deps_ok:
        print(f"\n🎉 Repository pattern is ready to use!")
        if not db_ok:
            print(f"💡 Entity examples will work without database")
            print(f"💡 Repository examples need Supabase configuration")
        print(f"\n🚀 Run: python3 run_examples.py")
    else:
        print(f"\n❌ Some issues need to be resolved first")
        show_environment_setup()

if __name__ == "__main__":
    main()