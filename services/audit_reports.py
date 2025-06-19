import logging
import json
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from decimal import Decimal
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings
from services.audit_report_versions import create_audit_report_version
from services.compliance_gaps import get_gaps_by_audit_session, get_compliance_gaps_statistics
from services.chat_history import get_audit_session_history
from services.audit_sessions import get_audit_session_by_id

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

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

        recommendations = _generate_recommendations(gaps, session_data)

        action_items = _generate_action_items(gaps)

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

def _generate_detailed_findings(chat_history, gaps, document_ids) -> Dict[str, Any]:
    return {
        "conversation_analysis": {
            "total_interactions": len(chat_history),
            "unique_documents_referenced": len(document_ids),
            "coverage_areas": list(set(item.get("compliance_domain") for item in chat_history if item.get("compliance_domain")))
        },
        "gap_analysis": {
            "gaps_by_type": _group_gaps_by_type(gaps),
            "regulatory_gaps": [gap for gap in gaps if gap.get("regulatory_requirement")],
            "process_gaps": [gap for gap in gaps if gap.get("gap_type") == "missing_policy"]
        },
        "document_coverage": {
            "documents_accessed": len(document_ids),
            "citation_frequency": {}  # Could be enhanced with actual citation counts
        }
    }

def _generate_recommendations(gaps, session_data) -> List[Dict[str, Any]]:
    recommendations = []

    gap_types = {}
    for gap in gaps:
        gap_type = gap.get("gap_type", "other")
        if gap_type not in gap_types:
            gap_types[gap_type] = []
        gap_types[gap_type].append(gap)

    for gap_type, type_gaps in gap_types.items():
        high_priority_gaps = [g for g in type_gaps if g.get("risk_level") in ["critical", "high"]]
        
        if gap_type == "missing_policy":
            recommendations.append({
                "priority": "high" if high_priority_gaps else "medium",
                "title": "Develop Missing Policies",
                "description": f"Create {len(type_gaps)} missing policy documents",
                "action_items": [f"Draft policy for: {gap.get('gap_title')}" for gap in type_gaps[:3]],
                "estimated_effort": f"{len(type_gaps) * 2} weeks",
                "compliance_impact": "high"
            })
        elif gap_type == "outdated_policy":
            recommendations.append({
                "priority": "medium",
                "title": "Update Outdated Policies",
                "description": f"Review and update {len(type_gaps)} outdated policies",
                "action_items": [f"Update: {gap.get('gap_title')}" for gap in type_gaps[:3]],
                "estimated_effort": f"{len(type_gaps)} weeks",
                "compliance_impact": "medium"
            })
    
    return recommendations

def _generate_action_items(gaps) -> List[Dict[str, Any]]:
    action_items = []

    critical_gaps = [g for g in gaps if g.get("risk_level") == "critical"]
    high_gaps = [g for g in gaps if g.get("risk_level") == "high"]

    for gap in critical_gaps:
        action_items.append({
            "title": f"URGENT: {gap.get('gap_title', 'Critical Gap')}",
            "description": gap.get("gap_description", ""),
            "priority": "critical",
            "due_date": (datetime.now(timezone.utc) + timezone.timedelta(days=7)).isoformat(),
            "assigned_to": gap.get("assigned_to"),
            "gap_id": gap.get("id"),
            "estimated_effort": "immediate"
        })

    for gap in high_gaps[:5]:  # Limit to top 5 high-priority gaps
        action_items.append({
            "title": gap.get("gap_title", "High Priority Gap"),
            "description": gap.get("gap_description", ""),
            "priority": "high",
            "due_date": (datetime.now(timezone.utc) + timezone.timedelta(days=30)).isoformat(),
            "assigned_to": gap.get("assigned_to"),
            "gap_id": gap.get("id"),
            "estimated_effort": "2-4 weeks"
        })
    
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

def _group_gaps_by_type(gaps) -> Dict[str, List[Dict[str, Any]]]:
    grouped = {}
    for gap in gaps:
        gap_type = gap.get("gap_type", "other")
        if gap_type not in grouped:
            grouped[gap_type] = []
        grouped[gap_type].append(gap)
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
        report_data.setdefault("recommendations", [])
        report_data.setdefault("action_items", [])
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

def update_audit_report(report_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        logger.info(f"Updating audit report {report_id}")

        update_data["last_modified_at"] = datetime.now(timezone.utc).isoformat()
        update_data["updated_at"] = datetime.now(timezone.utc).isoformat()

        if "report_status" in update_data:
            if update_data["report_status"] == "finalized" and "report_finalized_at" not in update_data:
                update_data["report_finalized_at"] = datetime.now(timezone.utc).isoformat()

        for key, value in update_data.items():
            if isinstance(value, Decimal):
                update_data[key] = float(value)

        filtered_update_data = {k: v for k, v in update_data.items() if v is not None}
        
        if not filtered_update_data:
            raise HTTPException(status_code=400, detail="No valid update data provided")
        
        resp = supabase.table(settings.supabase_table_audit_reports).update(filtered_update_data).eq("id", report_id).execute()
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase audit report update failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to update audit report: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Audit report {report_id} not found")
        
        logger.info(f"Updated audit report {report_id}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update audit report {report_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")