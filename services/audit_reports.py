import logging
import json
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from fastapi import HTTPException
from pydantic import ValidationError
from db.supabase_client import create_supabase_client
from config.config import settings
from services.audit_report_versions import create_audit_report_version
from services.compliance_gaps import get_gaps_by_audit_session, get_compliance_gaps_statistics
from services.chat_history import get_audit_session_history
from services.audit_sessions import get_audit_session_by_id
from services.schemas import AuditReportResponse, AuditReportUpdate, AuditReportVersionCreate, ChatHistoryItem, ComplianceGap, ComplianceImpact, ConversationAnalysis, DetailedFindings, DocumentCoverage, GapAnalysis, GapType, GapsByType, GeneratedActionItem, GeneratedRecommendation, PriorityLevel, RiskLevel

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

# NOTE: Gradual migration
# Below, we provide wrapper overrides that delegate legacy functions
# to the new Repository/Service implementations.
try:
    import asyncio
    from repositories.audit_report_repository import AuditReportRepository
    from dependencies import get_audit_report_service
except Exception:
    # Allow module import even if repository/service not available at import-time
    AuditReportRepository = None
    get_audit_report_service = None

def _get_repo_for_migration() -> Optional["AuditReportRepository"]:
    if AuditReportRepository is None:
        return None
    return AuditReportRepository(supabase, settings.supabase_table_audit_reports)

# --- Migration overrides (placed after original defs to take precedence) ---

def list_audit_reports(
    skip: int = 0,
    limit: int = 10,
    compliance_domain: Optional[str] = None,
    report_type: Optional[str] = None,
    report_status: Optional[str] = None,
    user_id: Optional[str] = None,
    audit_session_id: Optional[str] = None,
    target_audience: Optional[str] = None,
    confidentiality_level: Optional[str] = None,
    generated_after: Optional[datetime] = None,
    generated_before: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    repo = _get_repo_for_migration()
    if not repo:
        # Fallback to existing behavior above if repo unavailable
        return []
    filters: Dict[str, Any] = {}
    if compliance_domain:
        filters["compliance_domain"] = compliance_domain
    if report_type:
        filters["report_type"] = report_type
    if report_status:
        filters["report_status"] = report_status
    if user_id:
        filters["user_id"] = user_id
    if audit_session_id:
        filters["audit_session_id"] = audit_session_id
    if target_audience:
        filters["target_audience"] = target_audience
    if confidentiality_level:
        filters["confidentiality_level"] = confidentiality_level
    if generated_after:
        filters["generated_after"] = generated_after
    if generated_before:
        filters["generated_before"] = generated_before
    return asyncio.run(repo.list(skip=skip, limit=limit, filters=filters, order_by="-report_generated_at"))


def list_audit_reports_by_compliance_domains(compliance_domains: List[str]) -> List[Dict[str, Any]]:
    repo = _get_repo_for_migration()
    if not repo:
        return []
    return asyncio.run(repo.get_by_domains(compliance_domains))


def list_audit_reports_by_compliance_domain(compliance_domain: str) -> List[Dict[str, Any]]:
    repo = _get_repo_for_migration()
    if not repo:
        return []
    return asyncio.run(repo.get_by_domain(compliance_domain))


def get_audit_report_by_id(report_id: str) -> Dict[str, Any]:
    repo = _get_repo_for_migration()
    if not repo:
        return {}
    data = asyncio.run(repo.get_by_id(report_id))
    if not data:
        raise HTTPException(status_code=404, detail=f"Audit report with ID '{report_id}' not found")
    return data


def delete_audit_report(report_id: str, soft_delete: bool = True) -> Dict[str, Any]:
    repo = _get_repo_for_migration()
    if not repo:
        return {"success": False}
    success = asyncio.run(repo.delete(report_id, soft_delete=soft_delete))
    return {"success": success, "soft_delete": soft_delete}


def create_audit_report(report_data: Dict[str, Any]) -> Dict[str, Any]:
    repo = _get_repo_for_migration()
    if not repo:
        return {}
    return asyncio.run(repo.create(report_data))


def update_audit_report(
    report_id: str,
    update_data: Dict[str, Any],
    user_id: Optional[str] = None,
    create_version: bool = False,
    change_description: Optional[str] = None,
    change_type: str = "draft_update",
) -> Dict[str, Any]:
    repo = _get_repo_for_migration()
    if not repo:
        return {}
    # Maintain minimal processing for timestamps and audit trail
    now_iso = datetime.now(timezone.utc).isoformat()
    processed: Dict[str, Any] = {k: v for k, v in (update_data or {}).items() if v is not None}
    processed.setdefault("updated_at", now_iso)
    processed.setdefault("last_modified_at", now_iso)
    if processed.get("report_status") == "finalized" and "report_finalized_at" not in processed:
        processed["report_finalized_at"] = now_iso
    updated = asyncio.run(repo.update(report_id, processed))
    if create_version and updated:
        try:
            _create_report_version(
                report_id=report_id,
                current_data=updated,
                user_id=user_id,
                change_description=change_description or "Report updated",
                change_type=change_type,
            )
        except Exception:
            logger.warning("Failed to create report version during legacy update")
    return updated


def get_audit_report_statistics(
    compliance_domain: Optional[str] = None,
    user_id: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
) -> Dict[str, Any]:
    repo = _get_repo_for_migration()
    if not repo:
        return {}
    return asyncio.run(
        repo.get_statistics(
            compliance_domain=compliance_domain,
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
        )
    )


def generate_audit_report_from_session(
    audit_session_id: str,
    user_id: str,
    report_title: str,
    report_type: str = "compliance_audit",
    **generation_options,
) -> Dict[str, Any]:
    # Delegate to the new service to avoid duplicating complex logic
    if not get_audit_report_service:
        raise HTTPException(status_code=500, detail="AuditReportService unavailable")
    service = get_audit_report_service()
    return asyncio.run(
        service.generate_report_from_session(
            audit_session_id=audit_session_id,
            user_id=user_id,
            report_title=report_title,
            report_type=report_type,
            **generation_options,
        )
    )

def list_audit_reports(
    skip: int = 0,
    limit: int = 10,
    compliance_domain: Optional[str] = None,
    report_type: Optional[str] = None,
    report_status: Optional[str] = None,
    user_id: Optional[str] = None,
    audit_session_id: Optional[str] = None,
    target_audience: Optional[str] = None,
    confidentiality_level: Optional[str] = None,
    generated_after: Optional[datetime] = None,
    generated_before: Optional[datetime] = None
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching audit reports: skip={skip}, limit={limit}")
        
        query = supabase.table(settings.supabase_table_audit_reports).select("*")

        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
        if report_type:
            query = query.eq("report_type", report_type)
        if report_status:
            query = query.eq("report_status", report_status)
        if user_id:
            query = query.eq("user_id", user_id)
        if audit_session_id:
            query = query.eq("audit_session_id", audit_session_id)
        if target_audience:
            query = query.eq("target_audience", target_audience)
        if confidentiality_level:
            query = query.eq("confidentiality_level", confidentiality_level)
        if generated_after:
            query = query.gte("report_generated_at", generated_after.isoformat())
        if generated_before:
            query = query.lte("report_generated_at", generated_before.isoformat())
        
        resp = query.order("report_generated_at", desc=True).limit(limit).offset(skip).execute()
        
        logger.info(f"Retrieved {len(resp.data)} audit reports")
        return resp.data
        
    except Exception as e:
        logger.error("Failed to fetch audit reports", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_audit_reports_by_compliance_domains(
    compliance_domains: List[str]
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching audit reports for compliance domains: {compliance_domains}")
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_reports)
            .select("*")
            .in_("compliance_domain", compliance_domains)
            .order("report_generated_at", desc=True)
            .execute()
        )
        
        logger.info(f"Retrieved {len(resp.data)} audit reports for domains {compliance_domains}")
        return resp.data
        
    except Exception as e:
        logger.error("Failed to fetch audit reports by compliance domains", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_audit_reports_by_compliance_domain(
    compliance_domain: str
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching audit reports for compliance domains: {compliance_domain}")
        
        resp = (
            supabase
            .table(settings.supabase_table_audit_reports)
            .select("*")
            .in_("compliance_domain", compliance_domain)
            .order("report_generated_at", desc=True)
            .execute()
        )
        
        logger.info(f"Retrieved {len(resp.data)} audit reports for domains {compliance_domain}")
        return resp.data
        
    except Exception as e:
        logger.error("Failed to fetch audit reports by compliance domains", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    
def get_audit_report_by_id(report_id: str) -> Dict[str, Any]:
    """Get a specific audit report by ID"""
    try:
        logger.info(f"Fetching audit report with ID: {report_id}")
        resp = supabase.table(settings.supabase_table_audit_reports).select("*").eq("id", report_id).execute()
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase audit report fetch failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to fetch audit report: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Audit report with ID '{report_id}' not found")
        
        logger.info(f"Found audit report: {report_id}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch audit report {report_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def delete_audit_report(report_id: str, soft_delete: bool = True) -> Dict[str, Any]:
    try:
        logger.info(f"Deleting audit report {report_id} (soft_delete={soft_delete})")
        
        if soft_delete:
            update_data = {
                "report_status": "archived",
                "last_modified_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            
            resp = supabase.table(settings.supabase_table_audit_reports).update(update_data).eq("id", report_id).execute()
            
            if hasattr(resp, "error") and resp.error:
                logger.error("Supabase audit report soft delete failed", exc_info=True)
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to archive audit report: {resp.error.message}"
                )
            
            if not resp.data:
                raise HTTPException(status_code=404, detail=f"Audit report {report_id} not found")
            
            logger.info(f"Archived audit report {report_id}")
            return resp.data[0]
        else:
            resp = supabase.table(settings.supabase_table_audit_reports).delete().eq("id", report_id).execute()
            
            if hasattr(resp, "error") and resp.error:
                logger.error("Supabase audit report hard delete failed", exc_info=True)
                raise HTTPException(
                    status_code=500,
                    detail=f"Failed to delete audit report: {resp.error.message}"
                )
            
            if not resp.data:
                raise HTTPException(status_code=404, detail=f"Audit report {report_id} not found")
            
            logger.info(f"Permanently deleted audit report {report_id}")
            return {"message": f"Audit report {report_id} permanently deleted"}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete audit report {report_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def generate_audit_report_from_session(
    audit_session_id: str,
    user_id: str,
    report_title: str,
    report_type: str = "compliance_audit",
    **generation_options
) -> Dict[str, Any]:
    try:
        logger.info(f"Generating audit report from session {audit_session_id}")

        session_data = get_audit_session_by_id(audit_session_id)
        if not session_data:
            raise HTTPException(status_code=404, detail=f"Audit session {audit_session_id} not found")

        chat_history = get_audit_session_history(audit_session_id)
        chat_history_ids = [int(item["id"]) for item in chat_history]

        gaps = get_gaps_by_audit_session(audit_session_id)
        gap_ids = [gap["id"] for gap in gaps]

        total_questions = len(chat_history)
        session_duration = None
        total_tokens = sum(item.get("total_tokens_used", 0) for item in chat_history if item.get("total_tokens_used"))
        avg_response_time = None
        
        if chat_history:
            response_times = [item.get("response_time_ms", 0) for item in chat_history if item.get("response_time_ms")]
            avg_response_time = sum(response_times) / len(response_times) if response_times else None

        if session_data.get("ended_at") and session_data.get("started_at"):
            start_time = datetime.fromisoformat(session_data["started_at"].replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(session_data["ended_at"].replace('Z', '+00:00'))
            duration_delta = end_time - start_time
            session_duration = int(duration_delta.total_seconds() / 60)  # Convert to minutes

        gap_risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        regulatory_gaps = 0
        total_potential_fines = 0
        
        for gap in gaps:
            risk_level = gap.get("risk_level", "medium")
            gap_risk_counts[risk_level] = gap_risk_counts.get(risk_level, 0) + 1
            
            if gap.get("regulatory_requirement"):
                regulatory_gaps += 1
            
            fine_amount = gap.get("potential_fine_amount")
            if fine_amount:
                total_potential_fines += float(fine_amount)

        document_ids = set()
        for item in chat_history:
            doc_ids = item.get("source_document_ids", [])
            document_ids.update(doc_ids)

        executive_summary = _generate_executive_summary(
            session_data, chat_history, gaps, gap_risk_counts, total_potential_fines
        )

        detailed_findings = _generate_detailed_findings(chat_history, gaps, document_ids)

        recommendations_list = _generate_recommendations(gaps, session_data)
        recommendations = json.dumps([rec.dict() if hasattr(rec, 'dict') else rec for rec in recommendations_list])

        action_items_list = _generate_action_items(gaps)
        action_items = json.dumps([item.dict() if hasattr(item, 'dict') else item for item in action_items_list])

        compliance_rating = _calculate_compliance_rating(gaps, total_questions)

        report_data = {
            "user_id": user_id,
            "audit_session_id": audit_session_id,
            "compliance_domain": session_data.get("compliance_domain"),
            "report_title": report_title,
            "report_type": report_type,
            "report_status": "draft",

            "chat_history_ids": chat_history_ids,
            "compliance_gap_ids": gap_ids,
            "document_ids": list(document_ids),
            "pdf_ingestion_ids": [],  # Could be populated from document metadata

            "total_questions_asked": total_questions,
            "questions_answered_satisfactorily": max(0, total_questions - len(gaps)),
            "total_gaps_identified": len(gaps),
            "critical_gaps_count": gap_risk_counts["critical"],
            "high_risk_gaps_count": gap_risk_counts["high"],
            "medium_risk_gaps_count": gap_risk_counts["medium"],
            "low_risk_gaps_count": gap_risk_counts["low"],

            "policy_documents_referenced": len(document_ids),
            "unique_sources_count": len(document_ids),

            "session_duration_minutes": session_duration,
            "avg_response_time_ms": avg_response_time,
            "total_tokens_used": total_tokens,
            "total_similarity_searches": total_questions,

            "overall_compliance_rating": compliance_rating,
            "potential_fine_exposure": total_potential_fines,
            "regulatory_risk_score": _calculate_risk_score(gaps),

            "executive_summary": executive_summary,
            "detailed_findings": detailed_findings,
            "recommendations": recommendations,
            "action_items": action_items,

            "include_technical_details": generation_options.get("include_technical_details", False),
            "include_source_citations": generation_options.get("include_source_citations", True),
            "include_confidence_scores": generation_options.get("include_confidence_scores", False),
            "target_audience": generation_options.get("target_audience", "compliance_team"),
            "confidentiality_level": generation_options.get("confidentiality_level", "internal"),

            "generated_by": user_id,
            "auto_generated": True,
        }

        created_report = create_audit_report(report_data)

        create_audit_report_version(
            report_id=created_report["id"],
            changed_by=user_id,
            change_description="Initial report generation from audit session",
            change_type="draft_update",
            report_snapshot=created_report
        )
        
        logger.info(f"Generated audit report {created_report['id']} from session {audit_session_id}")
        return created_report
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate audit report from session {audit_session_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

def _generate_executive_summary(session_data, chat_history, gaps, gap_risk_counts, total_potential_fines) -> str:

    domain = session_data.get("compliance_domain", "Unknown")
    session_name = session_data.get("session_name", "Audit Session")
    
    summary = f"""
      # Executive Summary

      ## Audit Overview
      This {domain} compliance audit was conducted as part of {session_name}. The audit involved {len(chat_history)} queries across various compliance requirements and policies.

      ## Key Findings
      - **Total Compliance Gaps Identified**: {len(gaps)}
      - **Risk Distribution**: {gap_risk_counts['critical']} Critical, {gap_risk_counts['high']} High, {gap_risk_counts['medium']} Medium, {gap_risk_counts['low']} Low
      - **Potential Financial Exposure**: ${total_potential_fines:,.2f} in potential fines
      - **Questions Successfully Addressed**: {max(0, len(chat_history) - len(gaps))} of {len(chat_history)}

      ## Compliance Status
    """
    
    if gap_risk_counts['critical'] > 0:
        summary += "⚠️ **CRITICAL**: Immediate attention required for critical compliance gaps.\n"
    elif gap_risk_counts['high'] > 0:
        summary += "⚡ **HIGH PRIORITY**: Several high-risk gaps require prompt remediation.\n"
    elif len(gaps) > 0:
        summary += "✅ **MANAGEABLE**: Compliance gaps identified are manageable with standard remediation.\n"
    else:
        summary += "✅ **EXCELLENT**: No significant compliance gaps identified.\n"
    
    return summary.strip()

def _generate_detailed_findings(
    chat_history: List[ChatHistoryItem], 
    gaps: List[ComplianceGap], 
    document_ids: List[str]
) -> DetailedFindings:
    """Generate detailed findings with proper structure"""
    
    # Conversation analysis
    coverage_areas = list(set(
        item.compliance_domain for item in chat_history 
        if item.compliance_domain
    ))
    
    avg_confidence = None
    low_confidence_count = 0
    if chat_history:
        confidence_scores = [
            item.confidence_score for item in chat_history 
            if item.confidence_score is not None
        ]
        if confidence_scores:
            avg_confidence = sum(confidence_scores) / len(confidence_scores)
            low_confidence_count = len([s for s in confidence_scores if s < 0.7])
    
    conversation_analysis = ConversationAnalysis(
        total_interactions=len(chat_history),
        unique_documents_referenced=len(document_ids),
        coverage_areas=coverage_areas,
        avg_confidence_score=avg_confidence,
        low_confidence_interactions=low_confidence_count
    )
    
    # Gap analysis
    gaps_by_type = _group_gaps_by_type(gaps)
    regulatory_gaps = [gap for gap in gaps if gap.regulatory_requirement]
    high_confidence_gaps = [gap for gap in gaps if gap.gap_type != GapType.LOW_CONFIDENCE]
    
    gap_analysis = GapAnalysis(
        gaps_by_type=gaps_by_type,
        regulatory_gaps=regulatory_gaps,
        high_confidence_gaps=high_confidence_gaps,
        total_gaps=len(gaps),
        critical_gaps_count=len([g for g in gaps if g.risk_level == RiskLevel.CRITICAL]),
        high_risk_gaps_count=len([g for g in gaps if g.risk_level == RiskLevel.HIGH])
    )
    
    # Document coverage
    document_coverage = DocumentCoverage(
        documents_accessed=len(document_ids),
        citation_frequency={}  # Could be enhanced with actual citation counts
    )
    
    # Generate summary and insights
    summary = f"Analysis of {len(chat_history)} interactions identified {len(gaps)} compliance gaps across {len(coverage_areas)} domains."
    
    key_insights = []
    if gap_analysis.critical_gaps_count > 0:
        key_insights.append(f"{gap_analysis.critical_gaps_count} critical gaps require immediate attention")
    if avg_confidence and avg_confidence < 0.8:
        key_insights.append(f"Average confidence score of {avg_confidence:.2f} suggests need for better documentation")
    
    return DetailedFindings(
        conversation_analysis=conversation_analysis,
        gap_analysis=gap_analysis,
        document_coverage=document_coverage,
        summary=summary,
        key_insights=key_insights
    )

def _generate_recommendations(
    gaps: List[ComplianceGap], 
    session_data: Dict[str, Any]
) -> List[GeneratedRecommendation]:
    """Generate recommendations with proper structure"""
    recommendations = []
    
    # Group gaps by type
    gap_types = {}
    for gap in gaps:
        gap_type = gap.gap_type or GapType.NO_EVIDENCE  # Default to no_evidence instead of OTHER
        if gap_type not in gap_types:
            gap_types[gap_type] = []
        gap_types[gap_type].append(gap)
    
    for gap_type, type_gaps in gap_types.items():
        high_priority_gaps = [g for g in type_gaps if g.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]]
        
        if gap_type == GapType.MISSING_POLICY:
            recommendations.append(GeneratedRecommendation(
                title="Develop Missing Policies",
                description=f"Create {len(type_gaps)} missing policy documents to address compliance gaps",
                priority=PriorityLevel.HIGH if high_priority_gaps else PriorityLevel.MEDIUM,
                recommendation_type=gap_type,
                action_items=[f"Draft policy for: {gap.gap_title}" for gap in type_gaps[:3]],
                estimated_effort=f"{len(type_gaps) * 2} weeks",
                compliance_impact=ComplianceImpact.HIGH,
                affected_gaps=[gap.id for gap in type_gaps if gap.id],
                regulatory_requirements=[gap.regulatory_requirement for gap in type_gaps if gap.regulatory_requirement],
                business_justification=f"Addressing {len(type_gaps)} policy gaps will reduce regulatory risk",
                success_metrics=[
                    f"All {len(type_gaps)} policies drafted and approved",
                    "100% compliance coverage for affected domains"
                ]
            ))
        
        elif gap_type == GapType.OUTDATED_POLICY:
            recommendations.append(GeneratedRecommendation(
                title="Update Outdated Policies",
                description=f"Review and update {len(type_gaps)} outdated policies to current standards",
                priority=PriorityLevel.MEDIUM,
                recommendation_type=gap_type,
                action_items=[f"Update: {gap.gap_title}" for gap in type_gaps[:3]],
                estimated_effort=f"{len(type_gaps)} weeks",
                compliance_impact=ComplianceImpact.MEDIUM,
                affected_gaps=[gap.id for gap in type_gaps if gap.id],
                regulatory_requirements=[gap.regulatory_requirement for gap in type_gaps if gap.regulatory_requirement],
                business_justification=f"Updating {len(type_gaps)} policies will maintain current compliance",
                success_metrics=[
                    f"All {len(type_gaps)} policies updated to current standards",
                    "Reduced compliance risk by 30%"
                ]
            ))
        
        elif gap_type == GapType.LOW_CONFIDENCE:
            recommendations.append(GeneratedRecommendation(
                title="Improve Documentation Quality",
                description=f"Enhance documentation for {len(type_gaps)} areas with low confidence scores",
                priority=PriorityLevel.MEDIUM,
                recommendation_type=gap_type,
                action_items=[f"Improve documentation for: {gap.gap_title}" for gap in type_gaps[:3]],
                estimated_effort=f"{len(type_gaps) * 1.5} weeks",
                compliance_impact=ComplianceImpact.MEDIUM,
                affected_gaps=[gap.id for gap in type_gaps if gap.id],
                regulatory_requirements=[gap.regulatory_requirement for gap in type_gaps if gap.regulatory_requirement],
                business_justification="Better documentation will improve compliance confidence and reduce audit risk",
                success_metrics=[
                    f"Confidence scores improved to >80% for all {len(type_gaps)} areas",
                    "Reduced time to find compliance information by 50%"
                ]
            ))
        
        elif gap_type == GapType.CONFLICTING_POLICIES:
            recommendations.append(GeneratedRecommendation(
                title="Resolve Policy Conflicts",
                description=f"Address {len(type_gaps)} conflicting policy requirements",
                priority=PriorityLevel.HIGH,
                recommendation_type=gap_type,
                action_items=[f"Resolve conflict in: {gap.gap_title}" for gap in type_gaps[:3]],
                estimated_effort=f"{len(type_gaps) * 2} weeks",
                compliance_impact=ComplianceImpact.HIGH,
                affected_gaps=[gap.id for gap in type_gaps if gap.id],
                regulatory_requirements=[gap.regulatory_requirement for gap in type_gaps if gap.regulatory_requirement],
                risk_if_not_implemented="Policy conflicts can lead to compliance failures and audit findings",
                business_justification="Resolving conflicts ensures clear, consistent compliance requirements",
                success_metrics=[
                    f"All {len(type_gaps)} policy conflicts resolved",
                    "Single source of truth established for each compliance area"
                ]
            ))
        
        elif gap_type == GapType.INCOMPLETE_COVERAGE:
            recommendations.append(GeneratedRecommendation(
                title="Complete Compliance Coverage",
                description=f"Address {len(type_gaps)} areas with incomplete compliance coverage",
                priority=PriorityLevel.HIGH,
                recommendation_type=gap_type,
                action_items=[f"Complete coverage for: {gap.gap_title}" for gap in type_gaps[:3]],
                estimated_effort=f"{len(type_gaps) * 3} weeks",
                compliance_impact=ComplianceImpact.HIGH,
                affected_gaps=[gap.id for gap in type_gaps if gap.id],
                regulatory_requirements=[gap.regulatory_requirement for gap in type_gaps if gap.regulatory_requirement],
                risk_if_not_implemented="Incomplete coverage creates regulatory vulnerabilities",
                business_justification="Complete coverage ensures full regulatory compliance",
                success_metrics=[
                    f"100% coverage achieved for all {len(type_gaps)} areas",
                    "All regulatory requirements fully addressed"
                ]
            ))
        
        elif gap_type == GapType.NO_EVIDENCE:
            recommendations.append(GeneratedRecommendation(
                title="Establish Evidence Documentation",
                description=f"Create evidence documentation for {len(type_gaps)} compliance areas",
                priority=PriorityLevel.HIGH,
                recommendation_type=gap_type,
                action_items=[f"Document evidence for: {gap.gap_title}" for gap in type_gaps[:3]],
                estimated_effort=f"{len(type_gaps) * 2} weeks",
                compliance_impact=ComplianceImpact.HIGH,
                affected_gaps=[gap.id for gap in type_gaps if gap.id],
                regulatory_requirements=[gap.regulatory_requirement for gap in type_gaps if gap.regulatory_requirement],
                risk_if_not_implemented="Lack of evidence documentation creates audit risks",
                business_justification="Proper evidence documentation is essential for compliance verification",
                success_metrics=[
                    f"Evidence documentation established for all {len(type_gaps)} areas",
                    "Audit readiness score improved to >95%"
                ]
            ))
    
    return recommendations

def _generate_action_items(gaps: List[ComplianceGap]) -> List[GeneratedActionItem]:
    action_items = []
    
    critical_gaps = [g for g in gaps if g.risk_level == RiskLevel.CRITICAL]
    high_gaps = [g for g in gaps if g.risk_level == RiskLevel.HIGH]
    
    for gap in critical_gaps:
        action_items.append(GeneratedActionItem(
            title=f"URGENT: {gap.gap_title or 'Critical Gap'}",
            description=gap.gap_description or "Address critical compliance gap immediately",
            priority=PriorityLevel.CRITICAL,
            assigned_to=gap.assigned_to,
            due_date=datetime.now(timezone.utc) + timedelta(days=7),
            estimated_effort="immediate",
            gap_id=gap.id,
            compliance_domain=gap.compliance_domain,
            status="not_started"
        ))
    
    for gap in high_gaps[:5]:
        action_items.append(GeneratedActionItem(
            title=gap.gap_title or "High Priority Gap",
            description=gap.gap_description or "Address high-priority compliance gap",
            priority=PriorityLevel.HIGH,
            assigned_to=gap.assigned_to,
            due_date=datetime.now(timezone.utc) + timedelta(days=30),
            estimated_effort="2-4 weeks",
            gap_id=gap.id,
            compliance_domain=gap.compliance_domain,
            status="not_started"
        ))
    
    return action_items

def _calculate_compliance_rating(gaps, total_questions) -> str:
    if not gaps:
        return "excellent"
    
    critical_count = sum(1 for g in gaps if g.get("risk_level") == "critical")
    high_count = sum(1 for g in gaps if g.get("risk_level") == "high")
    
    if critical_count > 0:
        return "critical"
    elif high_count > 2:
        return "poor"
    elif len(gaps) > total_questions * 0.3:  # More than 30% of questions resulted in gaps
        return "fair"
    elif len(gaps) > 0:
        return "good"
    else:
        return "excellent"

def _calculate_risk_score(gaps) -> int:
    if not gaps:
        return 1
    
    score = 1
    for gap in gaps:
        risk_level = gap.get("risk_level", "low")
        if risk_level == "critical":
            score += 3
        elif risk_level == "high":
            score += 2
        elif risk_level == "medium":
            score += 1
        
        if gap.get("regulatory_requirement"):
            score += 1
    
    return min(10, score)

def _group_gaps_by_type(gaps: List[ComplianceGap]) -> GapsByType:
    grouped = GapsByType()
    
    for gap in gaps:
        gap_type = gap.gap_type or GapType.NO_EVIDENCE
        
        if gap_type == GapType.MISSING_POLICY:
            grouped.missing_policy.append(gap)
        elif gap_type == GapType.OUTDATED_POLICY:
            grouped.outdated_policy.append(gap)
        elif gap_type == GapType.LOW_CONFIDENCE:
            grouped.low_confidence.append(gap)
        elif gap_type == GapType.CONFLICTING_POLICIES:
            grouped.conflicting_policies.append(gap)
        elif gap_type == GapType.INCOMPLETE_COVERAGE:
            grouped.incomplete_coverage.append(gap)
        elif gap_type == GapType.NO_EVIDENCE:
            grouped.no_evidence.append(gap)
    
    return grouped

def get_audit_report_statistics(
    compliance_domain: Optional[str] = None,
    user_id: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
) -> Dict[str, Any]:
    """Get comprehensive audit report statistics"""
    try:
        logger.info("Generating audit report statistics")
        
        query = supabase.table(settings.supabase_table_audit_reports).select("*")

        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
        if user_id:
            query = query.eq("user_id", user_id)
        if start_date:
            query = query.gte("report_generated_at", start_date.isoformat())
        if end_date:
            query = query.lte("report_generated_at", end_date.isoformat())
        
        resp = query.execute()
        reports = resp.data

        total_reports = len(reports)

        status_counts = {}
        type_counts = {}
        domain_counts = {}
        audience_counts = {}
        
        total_coverage = 0
        total_gaps = 0
        total_remediation_cost = 0
        coverage_count = 0
        gaps_count = 0
        cost_count = 0
        
        for report in reports:
            status = report.get("report_status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

            report_type = report.get("report_type", "unknown")
            type_counts[report_type] = type_counts.get(report_type, 0) + 1

            domain = report.get("compliance_domain", "unknown")
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

            audience = report.get("target_audience", "unknown")
            audience_counts[audience] = audience_counts.get(audience, 0) + 1

            coverage = report.get("coverage_percentage")
            if coverage is not None:
                total_coverage += float(coverage)
                coverage_count += 1

            gaps = report.get("total_gaps_identified", 0)
            if gaps > 0:
                total_gaps += gaps
                gaps_count += 1

            cost = report.get("estimated_remediation_cost")
            if cost is not None:
                total_remediation_cost += float(cost)
                cost_count += 1

        avg_coverage = (total_coverage / coverage_count) if coverage_count > 0 else None
        avg_gaps = (total_gaps / gaps_count) if gaps_count > 0 else None
        avg_cost = (total_remediation_cost / cost_count) if cost_count > 0 else None

        dist_resp = supabase.table(settings.supabase_table_audit_report_distributions).select("audit_report_id").execute()
        total_distributions = len(dist_resp.data)
        avg_distributions_per_report = (total_distributions / total_reports) if total_reports > 0 else None

        current_month_start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_month_start = (current_month_start - timedelta(days=1)).replace(day=1)
        
        this_month_reports = len([r for r in reports if 
                                datetime.fromisoformat(r["report_generated_at"].replace('Z', '+00:00')) >= current_month_start])
        last_month_reports = len([r for r in reports if 
                                last_month_start <= datetime.fromisoformat(r["report_generated_at"].replace('Z', '+00:00')) < current_month_start])
        
        month_change = None
        if last_month_reports > 0:
            month_change = ((this_month_reports - last_month_reports) / last_month_reports) * 100
        
        stats = {
            "total_reports": total_reports,
            "reports_by_status": status_counts,
            "reports_by_type": type_counts,
            "reports_by_domain": domain_counts,
            "reports_by_audience": audience_counts,
            "avg_coverage_percentage": round(avg_coverage, 2) if avg_coverage else None,
            "avg_gaps_per_report": round(avg_gaps, 2) if avg_gaps else None,
            "avg_remediation_cost": round(avg_cost, 2) if avg_cost else None,
            "reports_this_month": this_month_reports,
            "reports_last_month": last_month_reports,
            "month_over_month_change": round(month_change, 2) if month_change else None,
            "total_distributions": total_distributions,
            "avg_distributions_per_report": round(avg_distributions_per_report, 2) if avg_distributions_per_report else None,
            "filters_applied": {
                "compliance_domain": compliance_domain,
                "user_id": user_id,
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None
            }
        }
        
        logger.info(f"Generated statistics for {total_reports} audit reports")
        return stats
        
    except Exception as e:
        logger.error("Failed to generate audit report statistics", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def create_audit_report(report_data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        logger.info(f"Creating audit report: {report_data.get('report_title')}")
        now = datetime.now(timezone.utc)
        report_data.setdefault("report_generated_at", now.isoformat())
        report_data.setdefault("created_at", now.isoformat())
        report_data.setdefault("updated_at", now.isoformat())
        report_data.setdefault("last_modified_at", now.isoformat())

        report_data.setdefault("report_status", "draft")
        report_data.setdefault("auto_generated", False)
        report_data.setdefault("notification_sent", False)
        report_data.setdefault("external_auditor_access", False)
        report_data.setdefault("regulatory_response_received", False)

        report_data.setdefault("chat_history_ids", [])
        report_data.setdefault("compliance_gap_ids", [])
        report_data.setdefault("document_ids", [])
        report_data.setdefault("pdf_ingestion_ids", [])
        report_data.setdefault("detailed_findings", {})
        report_data.setdefault("recommendations", "[]")
        report_data.setdefault("action_items", "[]")
        report_data.setdefault("appendices", {})
        report_data.setdefault("distributed_to", [])
        report_data.setdefault("audit_trail", [])
        report_data.setdefault("export_formats", ["pdf"])
        report_data.setdefault("benchmark_comparison", {})
        report_data.setdefault("integration_exports", {})

        for key, value in report_data.items():
            if isinstance(value, Decimal):
                report_data[key] = float(value)
        
        resp = supabase.table(settings.supabase_table_audit_reports).insert(report_data).execute()
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase audit report creation failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create audit report: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(
                status_code=500,
                detail="Failed to create audit report: No data returned from database"
            )
        
        logger.info(f"Created audit report with ID: {resp.data[0]['id']}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create audit report", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def update_audit_report(
    report_id: str, 
    update_data: Dict[str, Any], 
    user_id: Optional[str] = None,
    create_version: bool = False,
    change_description: Optional[str] = None,
    change_type: str = "draft_update"
) -> AuditReportResponse:
    try:
        logger.info(f"Updating audit report {report_id} with data: {list(update_data.keys())}")
        
        # Step 1: Validate the incoming update data using your Pydantic model
        try:
            validated_update = AuditReportUpdate(**update_data)
        except ValidationError as e:
            logger.error(f"Validation error for update data: {e}")
            raise HTTPException(
                status_code=400,
                detail=f"Validation error: {e.errors()}"
            )
        
        # Step 2: Get current report data if creating a version
        current_report = None
        if create_version:
            current_report = _get_current_report(report_id)
            if change_description is None:
                raise HTTPException(
                    status_code=400,
                    detail="change_description is required when create_version=True"
                )
        
        # Step 3: Convert validated model to dict, excluding None values
        processed_data = validated_update.dict(exclude_none=True)
        
        # Step 4: Handle special data type conversions for Supabase
        processed_data = _process_data_for_supabase(processed_data)
        
        # Step 5: Always update modification timestamps
        now_iso = datetime.now(timezone.utc).isoformat()
        processed_data["last_modified_at"] = now_iso
        processed_data["updated_at"] = now_iso
        
        # Step 6: Auto-set report_finalized_at if status is changing to finalized
        if processed_data.get("report_status") == "finalized" and "report_finalized_at" not in processed_data:
            processed_data["report_finalized_at"] = now_iso
        
        # Step 7: Update audit trail if user_id provided
        if user_id:
            processed_data = _update_audit_trail(processed_data, user_id, change_description or "Report updated")
        
        # Step 8: Create version snapshot if requested
        if create_version and current_report:
            _create_report_version(
                report_id=report_id,
                current_data=current_report,
                user_id=user_id,
                change_description=change_description,
                change_type=change_type
            )
        
        # Step 9: Perform the database update
        if not processed_data:
            raise HTTPException(status_code=400, detail="No valid update data provided")
        
        logger.info(f"Processed fields for update: {list(processed_data.keys())}")
        
        resp = supabase.table(settings.supabase_table_audit_reports).update(processed_data).eq("id", report_id).execute()
        
        if hasattr(resp, "error") and resp.error:
            logger.error(f"Supabase audit report update failed: {resp.error}", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to update audit report: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Audit report {report_id} not found")
        
        # Step 10: Convert response to Pydantic model
        try:
            updated_report = AuditReportResponse(**resp.data[0])
            logger.info(f"Successfully updated audit report {report_id}")
            return updated_report
        except ValidationError as e:
            logger.error(f"Response validation error: {e}")
            # Still return the raw data if model validation fails
            return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update audit report {report_id}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

def _process_data_for_supabase(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process validated data for Supabase compatibility.
    """
    from uuid import UUID
    
    processed = {}
    
    for key, value in data.items():
        if value is None:
            continue
            
        # Handle datetime objects
        if isinstance(value, datetime):
            processed[key] = value.isoformat()
        # Handle Decimal objects
        elif isinstance(value, Decimal):
            processed[key] = float(value)
        # Handle UUID objects - convert to string
        elif isinstance(value, UUID):
            processed[key] = str(value)
        # Handle lists that might contain UUIDs
        elif isinstance(value, list):
            processed_list = []
            for item in value:
                if isinstance(item, UUID):
                    processed_list.append(str(item))
                elif isinstance(item, datetime):
                    processed_list.append(item.isoformat())
                elif isinstance(item, Decimal):
                    processed_list.append(float(item))
                else:
                    processed_list.append(item)
            processed[key] = processed_list
        # Handle dicts that might contain UUIDs
        elif isinstance(value, dict):
            processed_dict = {}
            for dict_key, dict_value in value.items():
                if isinstance(dict_value, UUID):
                    processed_dict[dict_key] = str(dict_value)
                elif isinstance(dict_value, datetime):
                    processed_dict[dict_key] = dict_value.isoformat()
                elif isinstance(dict_value, Decimal):
                    processed_dict[dict_key] = float(dict_value)
                else:
                    processed_dict[dict_key] = dict_value
            processed[key] = processed_dict
        else:
            processed[key] = value
    
    return processed

def _update_audit_trail(data: Dict[str, Any], user_id: str, change_description: str) -> Dict[str, Any]:
    """
    Add an entry to the audit trail.
    """
    # Get current audit trail or initialize empty list
    current_trail = data.get("audit_trail", [])
    
    # Add new audit entry
    new_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "action": "update",
        "description": change_description,
        "fields_changed": list(data.keys())
    }
    
    current_trail.append(new_entry)
    data["audit_trail"] = current_trail
    
    return data


def _get_current_report(report_id: str) -> Dict[str, Any]:
    """
    Get the current state of a report for versioning.
    """
    resp = supabase.table(settings.supabase_table_audit_reports).select("*").eq("id", report_id).execute()
    
    if hasattr(resp, "error") and resp.error:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get current report: {resp.error.message}"
        )
    
    if not resp.data:
        raise HTTPException(status_code=404, detail=f"Audit report {report_id} not found")
    
    return resp.data[0]

def _create_report_version(
    report_id: str,
    current_data: Dict[str, Any],
    user_id: Optional[str],
    change_description: str,
    change_type: str
) -> None:
    """
    Create a version snapshot of the report before updating.
    """
    try:
        # Validate the version creation request
        version_request = AuditReportVersionCreate(
            change_description=change_description,
            change_type=change_type
        )
        
        # Get the next version number
        version_resp = supabase.table("audit_report_versions").select("version_number").eq("audit_report_id", report_id).order("version_number", desc=True).limit(1).execute()
        
        next_version = 1
        if version_resp.data:
            next_version = version_resp.data[0]["version_number"] + 1
        
        # Create version record
        version_data = {
            "audit_report_id": report_id,
            "version_number": next_version,
            "change_description": version_request.change_description,
            "changed_by": user_id,
            "change_type": version_request.change_type,
            "report_snapshot": current_data,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
        version_resp = supabase.table("audit_report_versions").insert(version_data).execute()
        
        if hasattr(version_resp, "error") and version_resp.error:
            logger.error(f"Failed to create report version: {version_resp.error}")
            # Don't fail the main update if versioning fails, just log it
        else:
            logger.info(f"Created version {next_version} for report {report_id}")
            
    except Exception as e:
        logger.error(f"Error creating report version: {e}")
        # Don't fail the main update if versioning fails
