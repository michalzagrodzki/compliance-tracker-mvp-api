"""
Example usage of AI Services for compliance recommendations.
This demonstrates the adapter pattern and service architecture for OpenAI integration.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from typing import Dict, Any

from adapters.openai_adapter import MockAIAdapter, AIRequest
from services.ai_service import AIService, create_ai_service
from services.compliance_recommendation_service import ComplianceRecommendationService
from dependencies import (
    get_ai_service,
    get_compliance_recommendation_service,
    get_compliance_gap_repository
)


async def adapter_examples():
    """Examples of using the OpenAI adapter directly."""
    
    print("=== OpenAI Adapter Examples ===\n")
    
    # Use mock adapter for demonstration
    adapter = MockAIAdapter(delay_ms=200)
    
    # 1. Simple text generation
    print("1. Simple text generation...")
    try:
        request = AIRequest(
            prompt="What are the key principles of GDPR compliance?",
            max_tokens=200,
            temperature=0.7
        )
        
        response = await adapter.generate_text(request)
        print(f"✅ Generated text ({response.tokens_used} tokens):")
        print(f"   {response.content[:100]}...")
        print(f"   Model: {response.model_used}")
        print(f"   Response time: {response.response_time_ms:.0f}ms")
        
    except Exception as e:
        print(f"❌ Text generation failed: {e}")
    
    # 2. Structured response generation
    print("\n2. Structured response generation...")
    try:
        schema = {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "key_points": {"type": "array", "items": {"type": "string"}},
                "risk_level": {"type": "string", "enum": ["low", "medium", "high"]}
            },
            "required": ["summary", "key_points", "risk_level"]
        }
        
        request = AIRequest(
            prompt="Analyze the compliance risk of not having a data retention policy",
            context={
                "role": "compliance analyst",
                "domain": "GDPR",
                "format": "structured"
            }
        )
        
        response = await adapter.generate_structured_response(request, schema)
        print(f"✅ Generated structured response:")
        print(f"   Content: {response.content}")
        print(f"   Structured data: {response.metadata.get('structured_data', {})}")
        
    except Exception as e:
        print(f"❌ Structured generation failed: {e}")


async def ai_service_examples():
    """Examples of using the AI Service with caching and business logic."""
    
    print("\n=== AI Service Examples ===\n")
    
    # Get AI service instance
    ai_service = get_ai_service()
    
    # 1. Text generation with caching
    print("1. Text generation with caching...")
    try:
        response1 = await ai_service.generate_text(
            prompt="What are the main requirements for ISO27001 compliance?",
            user_id="test-user-123"
        )
        print(f"✅ First request: {response1.response_time_ms:.0f}ms")
        
        # Same request should be cached
        response2 = await ai_service.generate_text(
            prompt="What are the main requirements for ISO27001 compliance?",
            user_id="test-user-123"
        )
        print(f"✅ Cached request: {response2.response_time_ms:.0f}ms")
        
        # Check cache stats
        cache_stats = ai_service.get_cache_stats()
        print(f"   Cache stats: {cache_stats}")
        
    except Exception as e:
        print(f"❌ AI service text generation failed: {e}")
    
    # 2. Sentiment analysis
    print("\n2. Sentiment analysis...")
    try:
        text = "I'm really concerned about our current data protection measures. The recent audit found several critical gaps that could lead to significant fines."
        
        sentiment = await ai_service.analyze_text_sentiment(text, user_id="test-user-123")
        print(f"✅ Sentiment analysis:")
        print(f"   Sentiment: {sentiment.get('sentiment', 'unknown')}")
        print(f"   Confidence: {sentiment.get('confidence_score', 0):.2f}")
        print(f"   Indicators: {sentiment.get('emotional_indicators', [])}")
        
    except Exception as e:
        print(f"❌ Sentiment analysis failed: {e}")
    
    # 3. Text summarization
    print("\n3. Text summarization...")
    try:
        long_text = """
        The General Data Protection Regulation (GDPR) is a comprehensive data protection law that came into effect in 2018. 
        It applies to all organizations that process personal data of EU residents, regardless of where the organization is located. 
        The regulation introduces strict requirements for data processing, including the need for lawful basis, data minimization, 
        accuracy, storage limitation, integrity and confidentiality, and accountability. Organizations must implement appropriate 
        technical and organizational measures to ensure compliance, including privacy by design and by default, data protection 
        impact assessments, and appointment of data protection officers where required.
        """
        
        summary = await ai_service.summarize_text(long_text, max_length=150, user_id="test-user-123")
        print(f"✅ Text summary:")
        print(f"   {summary}")
        
    except Exception as e:
        print(f"❌ Text summarization failed: {e}")


async def compliance_recommendation_examples():
    """Examples of using the ComplianceRecommendationService."""
    
    print("\n=== Compliance Recommendation Examples ===\n")
    
    try:
        # Get service instance
        recommendation_service = get_compliance_recommendation_service()
        
        # First, let's create a test compliance gap using the repository
        gap_repo = get_compliance_gap_repository()
        
        print("1. Creating test compliance gap...")
        from entities.compliance_gap import ComplianceGapCreate, GapType, RiskLevel, BusinessImpact
        
        test_gap_create = ComplianceGapCreate(
            user_id="test-user-123",
            audit_session_id="audit-session-456",
            compliance_domain="GDPR",
            gap_type=GapType.MISSING_POLICY,
            gap_category="Data Processing",
            gap_title="Missing Data Subject Rights Procedure",
            gap_description="No documented procedure for handling data subject access requests (DSARs)",
            original_question="How do we handle data subject access requests?",
            risk_level=RiskLevel.HIGH,
            business_impact=BusinessImpact.HIGH,
            regulatory_requirement=True
        )
        
        created_gap = await gap_repo.create(test_gap_create)
        print(f"✅ Created test gap: {created_gap.gap_title}")
        
        # 2. Generate recommendation for the gap
        print("\n2. Generating AI-powered recommendation...")
        try:
            recommendation = await recommendation_service.generate_gap_recommendation(
                gap_id=created_gap.id,
                user_id="test-user-123",
                recommendation_type="comprehensive",
                include_implementation_plan=True
            )
            
            print(f"✅ Generated recommendation:")
            print(f"   Root cause: {recommendation.get('root_cause_analysis', '')[:100]}...")
            print(f"   Actions: {len(recommendation.get('remediation_actions', []))} remediation actions")
            print(f"   Priority: {recommendation.get('priority_level', 'unknown')}")
            print(f"   Implementation phases: {len(recommendation.get('implementation_phases', []))}")
            
        except Exception as e:
            print(f"❌ Gap recommendation failed: {e}")
        
        # 3. Generate domain-level recommendations
        print("\n3. Generating domain-level recommendations...")
        try:
            domain_recommendations = await recommendation_service.generate_domain_recommendations(
                compliance_domain="GDPR",
                user_id="test-user-123",
                focus_area="Data Subject Rights",
                risk_threshold=RiskLevel.MEDIUM
            )
            
            print(f"✅ Generated domain recommendations:")
            print(f"   Assessment: {domain_recommendations.get('posture_assessment', '')[:100]}...")
            print(f"   Priority areas: {len(domain_recommendations.get('priority_areas', []))}")
            print(f"   Strategic recs: {len(domain_recommendations.get('strategic_recommendations', []))}")
            print(f"   Gap analysis: {domain_recommendations.get('gap_analysis', {})}")
            
        except Exception as e:
            print(f"❌ Domain recommendations failed: {e}")
        
        # 4. Generate remediation plan
        print("\n4. Generating remediation plan...")
        try:
            remediation_plan = await recommendation_service.generate_remediation_plan(
                gap_ids=[created_gap.id],
                user_id="test-user-123",
                timeline_weeks=8,
                resource_constraints={
                    "budget": "Limited budget available",
                    "staff": "2-3 people can be assigned part-time",
                    "external_help": "Can hire external consultant if needed"
                }
            )
            
            print(f"✅ Generated remediation plan:")
            print(f"   Summary: {remediation_plan.get('executive_summary', '')[:100]}...")
            print(f"   Phases: {len(remediation_plan.get('phases', []))}")
            print(f"   Milestones: {len(remediation_plan.get('milestones', []))}")
            print(f"   Total effort: {remediation_plan.get('total_estimated_effort', 'unknown')}")
            print(f"   Gaps included: {len(remediation_plan.get('gaps_included', []))}")
            
        except Exception as e:
            print(f"❌ Remediation plan failed: {e}")
        
        # Clean up - delete the test gap
        print("\n5. Cleaning up test data...")
        try:
            deleted = await gap_repo.delete(created_gap.id)
            if deleted:
                print("✅ Test gap deleted")
        except Exception as e:
            print(f"❌ Failed to delete test gap: {e}")
            
    except Exception as e:
        print(f"❌ Compliance recommendation examples failed: {e}")


def show_architecture_overview():
    """Show the architecture of the AI services."""
    
    print("\n=== AI Services Architecture Overview ===\n")
    
    print("📋 **Architecture Layers:**")
    print("1. **Adapter Layer** (`adapters/openai_adapter.py`)")
    print("   - OpenAIAdapter: Real OpenAI API integration")
    print("   - MockAIAdapter: Mock implementation for testing")
    print("   - BaseAIAdapter: Abstract interface")
    print()
    print("2. **Service Layer** (`services/ai_service.py`)")
    print("   - AIService: Business logic, caching, rate limiting")
    print("   - Text generation, structured responses, sentiment analysis")
    print("   - In-memory caching with TTL")
    print()
    print("3. **Domain Service** (`services/compliance_recommendation_service.py`)")
    print("   - ComplianceRecommendationService: Domain-specific AI operations")
    print("   - Gap recommendations, domain analysis, remediation plans")
    print("   - Integration with compliance gap repository")
    print()
    print("4. **Dependency Injection** (`dependencies.py`)")
    print("   - Auto-configures OpenAI vs Mock based on API key availability")
    print("   - Singleton pattern with proper dependency graph")
    print("   - FastAPI dependency annotations")
    print()
    print("🔧 **Key Features:**")
    print("• **Adapter Pattern**: Easy to swap AI providers")
    print("• **Caching**: Reduces API calls and costs")
    print("• **Rate Limiting**: Prevents API quota exhaustion")
    print("• **Error Handling**: Comprehensive exception handling")
    print("• **Structured Responses**: JSON schema validation")
    print("• **Business Logic**: Domain-specific recommendations")
    print("• **Access Control**: User permission integration")
    print("• **Audit Logging**: Complete request/response tracking")
    print()
    print("💡 **Benefits over Repository Pattern:**")
    print("• Repository = Data persistence (CRUD operations)")
    print("• Adapter = External service integration (API calls)")
    print("• Service = Business logic (caching, validation, orchestration)")
    print("• This architecture is perfect for AI/external APIs!")


async def main():
    """Run all examples."""
    print("🤖 AI Services Architecture - OpenAI Integration\n")
    
    # Show architecture overview
    show_architecture_overview()
    
    # Run examples
    try:
        await adapter_examples()
        await ai_service_examples()
        await compliance_recommendation_examples()
        
    except Exception as e:
        print(f"\n❌ Examples failed: {e}")
        print("💡 Make sure your dependencies are configured correctly")
    
    print("\n✨ AI Services Examples Complete!")


if __name__ == "__main__":
    asyncio.run(main())