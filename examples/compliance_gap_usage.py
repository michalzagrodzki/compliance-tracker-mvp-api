"""
Example usage of the ComplianceGap Repository pattern.
This demonstrates how to use the new compliance gap repository-based architecture.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from datetime import datetime, timedelta
from decimal import Decimal
from typing import List

from entities.compliance_gap import (
    ComplianceGap, 
    ComplianceGapCreate, 
    ComplianceGapUpdate, 
    ComplianceGapFilter,
    GapType, 
    RiskLevel, 
    BusinessImpact, 
    GapStatus,
    DetectionMethod
)
from repositories.compliance_gap_repository import ComplianceGapRepository
from services.compliance_gap_service import ComplianceGapService
from dependencies import (
    get_supabase_client, 
    get_compliance_gap_repository, 
    get_compliance_gap_service,
    get_user_repository
)


async def repository_examples():
    """Examples of using the ComplianceGap repository directly."""
    
    # Get repository instance
    gap_repo = get_compliance_gap_repository()
    
    print("=== ComplianceGap Repository Pattern Examples ===\n")
    
    # 1. Create a new compliance gap
    print("1. Creating a new compliance gap...")
    try:
        new_gap = ComplianceGapCreate(
            user_id="test-user-123",
            audit_session_id="audit-session-456",
            compliance_domain="GDPR",
            gap_type=GapType.MISSING_POLICY,
            gap_category="Data Processing",
            gap_title="Missing Data Retention Policy",
            gap_description="No clear policy found for data retention periods for user data",
            original_question="What is our data retention policy for user personal data?",
            expected_answer_type="policy_document",
            search_terms_used=["data retention", "personal data", "GDPR"],
            similarity_threshold_used=Decimal("0.75"),
            best_match_score=Decimal("0.45"),
            risk_level=RiskLevel.HIGH,
            business_impact=BusinessImpact.HIGH,
            regulatory_requirement=True,
            potential_fine_amount=Decimal("50000.00"),
            confidence_score=Decimal("0.85")
        )
        
        created_gap = await gap_repo.create(new_gap)
        print(f"✅ Created gap: {created_gap.gap_title} (ID: {created_gap.id})")
        
        # Store the ID for other examples
        gap_id = created_gap.id
        
    except Exception as e:
        print(f"❌ Failed to create gap: {e}")
        return
    
    # 2. Get gap by ID
    print("\n2. Retrieving gap by ID...")
    try:
        gap = await gap_repo.get_by_id(gap_id)
        if gap:
            print(f"✅ Found gap: {gap.gap_title}")
            print(f"   Risk Level: {gap.risk_level.value}")
            print(f"   Status: {gap.status.value}")
            print(f"   Detected: {gap.detected_at}")
        else:
            print("❌ Gap not found")
    except Exception as e:
        print(f"❌ Failed to get gap: {e}")
    
    # 3. Update gap
    print("\n3. Updating gap...")
    try:
        update_data = ComplianceGapUpdate(
            gap_description="Updated: No clear policy found for data retention periods. Urgent compliance issue.",
            risk_level=RiskLevel.CRITICAL,
            assigned_to="compliance-officer-789",
            due_date=datetime.utcnow() + timedelta(days=7)
        )
        
        updated_gap = await gap_repo.update(gap_id, update_data)
        if updated_gap:
            print(f"✅ Updated gap: Risk level now {updated_gap.risk_level.value}")
            print(f"   Assigned to: {updated_gap.assigned_to}")
            print(f"   Due date: {updated_gap.due_date}")
    except Exception as e:
        print(f"❌ Failed to update gap: {e}")
    
    # 4. Update status
    print("\n4. Updating gap status...")
    try:
        updated_gap = await gap_repo.update_status(
            gap_id, 
            GapStatus.ACKNOWLEDGED, 
            "compliance-officer-789",
            "Acknowledged the gap. Will create policy document."
        )
        if updated_gap:
            print(f"✅ Status updated to: {updated_gap.status.value}")
            print(f"   Acknowledged at: {updated_gap.acknowledged_at}")
            print(f"   Resolution notes: {updated_gap.resolution_notes}")
    except Exception as e:
        print(f"❌ Failed to update status: {e}")
    
    # 5. List gaps with filters
    print("\n5. Listing gaps with filters...")
    try:
        filters = ComplianceGapFilter(
            compliance_domain="GDPR",
            risk_level=RiskLevel.CRITICAL,
            regulatory_requirement=True
        )
        gaps = await gap_repo.list(limit=10, filters=filters)
        print(f"✅ Found {len(gaps)} critical GDPR regulatory gaps")
        
        for gap in gaps[:3]:  # Show first 3
            print(f"   - {gap.gap_title} ({gap.risk_level.value})")
            
    except Exception as e:
        print(f"❌ Failed to list gaps: {e}")
    
    # 6. Get statistics
    print("\n6. Getting gap statistics...")
    try:
        stats = await gap_repo.get_statistics("GDPR")
        print(f"✅ GDPR Gap Statistics:")
        print(f"   Total gaps: {stats['total_gaps']}")
        print(f"   Regulatory gaps: {stats['regulatory_gaps']}")
        print(f"   Potential fines: ${stats['total_potential_fines']}")
        print(f"   Resolution rate: {stats['resolution_rate_percent']:.1f}%")
        print(f"   Risk breakdown: {stats['risk_level_breakdown']}")
        
    except Exception as e:
        print(f"❌ Failed to get statistics: {e}")
    
    # 7. Clean up - delete the test gap
    print("\n7. Cleaning up test data...")
    try:
        deleted = await gap_repo.delete(gap_id)
        if deleted:
            print("✅ Test gap deleted")
        
    except Exception as e:
        print(f"❌ Failed to delete gap: {e}")


async def service_examples():
    """Examples of using the ComplianceGapService with business logic."""
    
    print("\n=== Service Layer Examples ===\n")
    
    # Get service instance
    gap_service = get_compliance_gap_service()
    
    # 1. Create gap via service (includes access control)
    print("1. Creating gap via service...")
    try:
        gap_create = ComplianceGapCreate(
            user_id="test-user-123",
            audit_session_id="audit-session-789",
            compliance_domain="ISO27001",
            gap_type=GapType.INCOMPLETE_COVERAGE,
            gap_category="Access Control",
            gap_title="Incomplete Access Control Matrix",
            gap_description="Access control matrix missing for several system components",
            original_question="What are the access controls for the HR system?",
            risk_level=RiskLevel.MEDIUM,
            business_impact=BusinessImpact.MEDIUM,
            regulatory_requirement=False
        )
        
        created_gap = await gap_service.create_gap(
            gap_create, 
            user_id="test-user-123",
            ip_address="127.0.0.1",
            user_agent="Test Client"
        )
        print(f"✅ Service created gap: {created_gap.gap_title}")
        service_gap_id = created_gap.id
        
    except Exception as e:
        print(f"❌ Service creation failed: {e}")
        return
    
    # 2. Get gap with access control
    print("\n2. Getting gap via service (with access control)...")
    try:
        gap = await gap_service.get_gap_by_id(service_gap_id, "test-user-123")
        print(f"✅ Service retrieved gap: {gap.gap_title}")
        print(f"   Age in days: {gap.get_age_in_days()}")
        
    except Exception as e:
        print(f"❌ Service retrieval failed: {e}")
    
    # 3. Assign gap
    print("\n3. Assigning gap via service...")
    try:
        due_date = datetime.utcnow() + timedelta(days=14)
        assigned_gap = await gap_service.assign_gap(
            service_gap_id,
            "compliance-officer-789",
            "test-user-123",
            due_date
        )
        print(f"✅ Gap assigned to: {assigned_gap.assigned_to}")
        print(f"   Due date: {assigned_gap.due_date}")
        
    except Exception as e:
        print(f"❌ Service assignment failed: {e}")
    
    # 4. Update status via service
    print("\n4. Updating status via service...")
    try:
        updated_gap = await gap_service.update_gap_status(
            service_gap_id,
            GapStatus.IN_PROGRESS,
            "compliance-officer-789",
            "Started working on access control matrix updates"
        )
        print(f"✅ Status updated to: {updated_gap.status.value}")
        
    except Exception as e:
        print(f"❌ Service status update failed: {e}")
    
    # 5. List gaps via service (with access control)
    print("\n5. Listing gaps via service...")
    try:
        filters = ComplianceGapFilter(
            compliance_domain="ISO27001",
            status=GapStatus.IN_PROGRESS
        )
        gaps = await gap_service.list_gaps("test-user-123", filters=filters)
        print(f"✅ Service found {len(gaps)} in-progress ISO27001 gaps")
        
    except Exception as e:
        print(f"❌ Service listing failed: {e}")
    
    # Clean up
    print("\n6. Cleaning up service test data...")
    try:
        # For cleanup, we'll use the repository directly
        gap_repo = get_compliance_gap_repository()
        deleted = await gap_repo.delete(service_gap_id)
        if deleted:
            print("✅ Service test gap deleted")
        
    except Exception as e:
        print(f"❌ Failed to delete service gap: {e}")


def show_entity_features():
    """Demonstrate ComplianceGap entity model features."""
    
    print("\n=== Entity Model Features ===\n")
    
    # Create a gap entity
    gap_data = {
        "id": "demo-gap-123",
        "user_id": "user-456",
        "audit_session_id": "audit-789",
        "compliance_domain": "GDPR",
        "gap_type": "missing_policy",
        "gap_category": "Data Processing",
        "gap_title": "Demo Compliance Gap",
        "gap_description": "This is a demo gap for testing",
        "original_question": "What is our demo policy?",
        "risk_level": "high",
        "business_impact": "medium",
        "regulatory_requirement": True,
        "potential_fine_amount": "25000.00",
        "status": "identified",
        "detected_at": datetime.utcnow(),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "confidence_score": "0.78"
    }
    
    gap = ComplianceGap.from_dict(gap_data)
    
    print("1. Gap entity created:")
    print(f"   Title: {gap.gap_title}")
    print(f"   Risk Level: {gap.risk_level.value}")
    print(f"   Status: {gap.status.value}")
    print(f"   Potential Fine: ${gap.potential_fine_amount}")
    
    print("\n2. Testing business methods:")
    print(f"   Is critical: {gap.is_critical()}")
    print(f"   Is regulatory: {gap.is_regulatory()}")
    print(f"   Is resolved: {gap.is_resolved()}")
    print(f"   Is assigned: {gap.is_assigned()}")
    print(f"   Age in days: {gap.get_age_in_days()}")
    
    print("\n3. Testing state changes:")
    gap.acknowledge("compliance-officer-123")
    print(f"   Status after acknowledgment: {gap.status.value}")
    print(f"   Acknowledged at: {gap.acknowledged_at}")
    
    gap.assign_to("specialist-456", datetime.utcnow() + timedelta(days=30))
    print(f"   Assigned to: {gap.assigned_to}")
    print(f"   Due date: {gap.due_date}")
    
    gap.start_resolution()
    print(f"   Status after starting resolution: {gap.status.value}")
    
    gap.resolve("Policy document created and approved")
    print(f"   Status after resolution: {gap.status.value}")
    print(f"   Resolved at: {gap.resolved_at}")
    print(f"   Resolution time: {gap.get_resolution_time_days()} days")


async def main():
    """Run all examples."""
    print("🚀 ComplianceGap Repository Pattern Implementation\n")
    
    # Show entity features (doesn't require DB)
    show_entity_features()
    
    # Repository and service examples (require DB connection)
    try:
        await repository_examples()
        await service_examples()
        
    except Exception as e:
        print(f"\n❌ Database connection error: {e}")
        print("💡 Make sure your Supabase connection is configured correctly")
    
    print("\n✨ ComplianceGap Repository Pattern Examples Complete!")


if __name__ == "__main__":
    asyncio.run(main())