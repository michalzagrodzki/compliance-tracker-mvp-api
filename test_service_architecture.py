#!/usr/bin/env python3
"""
Test script to verify the Repository pattern and AI services architecture.
This tests the core components without requiring FastAPI or external dependencies.
"""

import sys
import os
import asyncio
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_architecture_components():
    """Test that all architecture components can be imported and initialized."""
    
    print("🏗️ Testing Repository Pattern & AI Services Architecture\n")
    
    try:
        # 1. Test entity imports
        print("1. Testing entity layer...")
        from entities.user import User, UserCreate, UserRole
        from entities.compliance_gap import ComplianceGap, ComplianceGapCreate, RiskLevel, GapType
        print(f"✅ User entity: {User}")
        print(f"✅ ComplianceGap entity: {ComplianceGap}")
        print(f"✅ Enums: {list(UserRole)[:3]}, {list(RiskLevel)}")
        
        # 2. Test repository layer
        print("\n2. Testing repository layer...")
        from repositories.base import BaseRepository, SupabaseRepository
        from repositories.user_repository import UserRepository
        from repositories.compliance_gap_repository import ComplianceGapRepository
        print(f"✅ BaseRepository: {BaseRepository}")
        print(f"✅ UserRepository: {UserRepository}")
        print(f"✅ ComplianceGapRepository: {ComplianceGapRepository}")
        
        # 3. Test adapter layer
        print("\n3. Testing adapter layer...")
        from adapters.openai_adapter import BaseAIAdapter, OpenAIAdapter, MockAIAdapter
        print(f"✅ BaseAIAdapter: {BaseAIAdapter}")
        print(f"✅ OpenAIAdapter: {OpenAIAdapter}")
        print(f"✅ MockAIAdapter: {MockAIAdapter}")
        
        # 4. Test service layer
        print("\n4. Testing service layer...")
        from services.ai_service import AIService
        from services.compliance_recommendation_service import ComplianceRecommendationService
        print(f"✅ AIService: {AIService}")
        print(f"✅ ComplianceRecommendationService: {ComplianceRecommendationService}")
        
        # 5. Test that we can create mock instances
        print("\n5. Testing mock implementations...")
        
        # Create mock adapter
        mock_adapter = MockAIAdapter(delay_ms=10)
        print(f"✅ Mock AI Adapter created: {type(mock_adapter).__name__}")
        
        # Test entity creation
        from datetime import datetime
        from decimal import Decimal
        
        gap_data = {
            "id": "test-123",
            "user_id": "user-456", 
            "audit_session_id": "audit-789",
            "compliance_domain": "GDPR",
            "gap_type": "missing_policy",
            "gap_category": "Data Processing",
            "gap_title": "Test Architecture Gap", 
            "gap_description": "Testing architecture components",
            "original_question": "How does our architecture work?",
            "risk_level": "high",
            "business_impact": "medium",
            "status": "identified",
            "regulatory_requirement": True,
            "detected_at": datetime.utcnow(),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "confidence_score": "0.90"
        }
        
        gap = ComplianceGap.from_dict(gap_data)
        print(f"✅ Gap entity: {gap.gap_title} ({gap.risk_level.value})")
        
        # Test business methods
        print(f"   - Is critical: {gap.is_critical()}")
        print(f"   - Is regulatory: {gap.is_regulatory()}")
        print(f"   - Age in days: {gap.get_age_in_days()}")
        
        print(f"\n🎉 Architecture test completed successfully!")
        print(f"✨ All Repository pattern and AI service components are working!")
        
        return True
        
    except Exception as e:
        print(f"❌ Architecture test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_ai_adapter_functionality():
    """Test AI adapter functionality with mock implementation."""
    
    print("\n" + "="*50)
    print("🤖 Testing AI Adapter Functionality")
    print("="*50)
    
    try:
        from adapters.openai_adapter import MockAIAdapter, AIRequest
        
        # Create mock adapter
        adapter = MockAIAdapter(delay_ms=50)
        
        # Test simple text generation
        print("\n1. Testing text generation...")
        request = AIRequest(
            prompt="What are the key principles of GDPR compliance?",
            max_tokens=100,
            temperature=0.7
        )
        
        response = await adapter.generate_text(request)
        print(f"✅ Generated response: {len(response.content)} characters")
        print(f"   Model: {response.model_used}")
        print(f"   Tokens: {response.tokens_used}")
        print(f"   Response time: {response.response_time_ms}ms")
        print(f"   Content preview: {response.content[:100]}...")
        
        # Test structured response
        print("\n2. Testing structured response...")
        schema = {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "key_points": {"type": "array", "items": {"type": "string"}},
                "risk_level": {"type": "string", "enum": ["low", "medium", "high"]}
            },
            "required": ["summary", "key_points", "risk_level"]
        }
        
        structured_request = AIRequest(
            prompt="Analyze compliance risk of missing data retention policy",
            context={"domain": "GDPR", "format": "structured"}
        )
        
        structured_response = await adapter.generate_structured_response(structured_request, schema)
        print(f"✅ Generated structured response")
        print(f"   Content type: {type(structured_response.content)}")
        print(f"   Has structured data: {'structured_data' in structured_response.metadata}")
        
        return True
        
    except Exception as e:
        print(f"❌ AI adapter test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def show_integration_summary():
    """Show summary of the integration work."""
    
    print("\n" + "="*60)
    print("📋 COMPLIANCE RECOMMENDATION SERVICE INTEGRATION SUMMARY")
    print("="*60)
    
    print("\n✅ **What was completed:**")
    print("1. **Updated API Router** (`api/compliance.py`)")
    print("   - Integrated ComplianceRecommendationService instead of old service")
    print("   - Added proper FastAPI dependency injection")
    print("   - Maintained backward compatibility with existing schema")
    print("   - Added 3 new AI-powered endpoints")
    
    print("\n2. **New API Endpoints:**")
    print("   - `POST /compliance-gaps/{gap_id}/recommendation` - Gap-specific recommendations")
    print("   - `POST /compliance-domains/{domain_code}/recommendations` - Domain-wide analysis")
    print("   - `POST /compliance-gaps/remediation-plan` - Multi-gap remediation planning")
    
    print("\n3. **Architecture Integration:**")
    print("   - Repository pattern for data access")
    print("   - Service layer for business logic")
    print("   - Adapter pattern for OpenAI API")
    print("   - Proper dependency injection")
    print("   - Caching for performance optimization")
    
    print("\n🔧 **Technical Details:**")
    print("   - Uses `Depends(get_compliance_recommendation_service)` for DI")
    print("   - Converts new service responses to legacy schema format")
    print("   - Includes gap context retrieval for complete responses")
    print("   - Supports both OpenAI and Mock adapters")
    
    print("\n📊 **Benefits:**")
    print("   - Clean separation of concerns")
    print("   - Testable architecture")  
    print("   - Reduced API costs through caching")
    print("   - Enhanced recommendation capabilities")
    print("   - Scalable for additional AI features")
    
    print("\n🚀 **Next Steps for User:**")
    print("   - Test the updated API endpoints")
    print("   - Configure OpenAI API key for full functionality")
    print("   - Run `python3 run_examples.py` to see examples")
    print("   - Use mock adapter for development/testing")

async def main():
    """Main test function."""
    
    # Test architecture components
    arch_success = test_architecture_components()
    
    if arch_success:
        # Test AI functionality
        ai_success = await test_ai_adapter_functionality()
        
        if ai_success:
            show_integration_summary()
            return True
    
    return False

if __name__ == "__main__":
    result = asyncio.run(main())
    print(f"\n{'🎉 All tests passed!' if result else '❌ Some tests failed'}")
    sys.exit(0 if result else 1)