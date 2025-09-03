import time
from fastapi import APIRouter, Request, HTTPException
from slowapi import Limiter
from slowapi.util import get_remote_address

from auth.decorators import ValidatedUser, authorize
from dependencies import AuditLogServiceDep
from entities.audit_log import AuditLogCreate
from services.control_risk_prioritization import (
    generate_control_risk_prioritization,
    calculate_risk_prioritization_metrics,
    ControlRiskPrioritizationResponse
)
from services.schemas import ThreatIntelligenceRequest
from config.config import settings

router = APIRouter(prefix="/audit-reports/risk-prioritization", tags=["Audit Reports"])
limiter = Limiter(key_func=get_remote_address)


@router.post("",
    response_model=ControlRiskPrioritizationResponse,
    summary="Generate control risk prioritization from audit report and compliance gaps",
    description="Creates a professional control risk prioritization analysis using OpenAI API based on audit report data and identified compliance gaps. Returns formatted markdown suitable for C-level executives and board members with strategic business intelligence."
)
@limiter.limit("10/minute")
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def create_control_risk_prioritization(
    request_data: ThreatIntelligenceRequest,
    request: Request,
    audit_log_service: AuditLogServiceDep = None,
    current_user: ValidatedUser = None
) -> ControlRiskPrioritizationResponse:
    start_time = time.time()
    
    # Extract request metadata
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # Validate that compliance gaps match the audit session
    if request_data.compliance_gaps:
        mismatched_gaps = [
            gap for gap in request_data.compliance_gaps 
            if gap.audit_session_id != request_data.audit_report.audit_session_id
        ]
        if mismatched_gaps:
            raise HTTPException(
                status_code=400, 
                detail=f"Found {len(mismatched_gaps)} compliance gaps with mismatched audit_session_id"
            )

    audit_report_dict = request_data.audit_report.model_dump()
    compliance_gaps_list = [gap.model_dump() for gap in request_data.compliance_gaps]

    try:
        risk_analysis = generate_control_risk_prioritization(
            audit_report=audit_report_dict,
            compliance_gaps=compliance_gaps_list,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail="An unexpected error occurred while generating the control risk prioritization analysis"
        )
    
    end_time = time.time()
    response_time_ms = int((end_time - start_time) * 1000)

    # Calculate risk metrics
    metrics = calculate_risk_prioritization_metrics(audit_report_dict, request_data.compliance_gaps)

    generation_metadata = {
        "generation_time_ms": response_time_ms,
        "analysis_type": "control_risk_prioritization",
        "ip_address": ip_address,
        "user_agent": user_agent,
        "openai_model": settings.openai_model,
        "audit_report_title": request_data.audit_report.report_title,
        "compliance_domain": request_data.audit_report.compliance_domain,
        "target_audience": request_data.audit_report.target_audience,
        "confidentiality_level": request_data.audit_report.confidentiality_level,
        "documents_reviewed": len(request_data.audit_report.document_ids or []),
        "chat_sessions": len(request_data.audit_report.chat_history_ids or []),
        "pdf_sources": len(request_data.audit_report.pdf_ingestion_ids or []),
        "company_size": "Medium Enterprise",
        "industry_sector": "IT Services",
        "geographic_footprint": "Multi-regional operations",
        "average_confidence_score": (
            sum(gap.confidence_score for gap in request_data.compliance_gaps) / len(request_data.compliance_gaps)
            if request_data.compliance_gaps else 0.0
        ),
        "average_false_positive_likelihood": (
            sum(gap.false_positive_likelihood for gap in request_data.compliance_gaps) / len(request_data.compliance_gaps)
            if request_data.compliance_gaps else 0.0
        ),
        "iso27001_control_families_total": 14,
        "risk_prioritization_methodology": "High Risk + High Impact = Priority 1, Strategic combinations = Priority 2, Others = Priority 3"
    }

    # Create audit log (best-effort via service)
    try:
        audit_log = AuditLogCreate(
            object_type="audit_session",
            object_id=str(request_data.audit_report.audit_session_id),
            action="create",
            user_id=str(current_user.id),
            compliance_domain=request_data.audit_report.compliance_domain,
            audit_session_id=str(request_data.audit_report.audit_session_id),
            risk_level="high",
            details={
                "audit report title": request_data.audit_report.report_title,
                "summary type": "control risk prioritization",
            },
            ip_address=ip_address,
            user_agent=user_agent,
            tags=[],
        )
        await audit_log_service.create_audit_log(audit_log, str(current_user.id))
    except Exception:
        pass
    
    return ControlRiskPrioritizationResponse(
        risk_prioritization_analysis=risk_analysis,
        audit_session_id=request_data.audit_report.audit_session_id,
        compliance_domain=request_data.audit_report.compliance_domain,
        total_gaps=metrics["total_gaps"],
        high_risk_gaps=metrics["high_risk_gaps"],
        medium_risk_gaps=metrics["medium_risk_gaps"],
        low_risk_gaps=metrics["low_risk_gaps"],
        regulatory_gaps=metrics["regulatory_gaps"],
        total_potential_fines=metrics["total_potential_fines"],
        affected_control_families=metrics["affected_control_families"],
        certification_readiness_score=metrics["certification_readiness_score"],
        estimated_investment_range=metrics["estimated_investment_range"],
        priority_1_gaps=metrics["priority_1_gaps"],
        priority_2_gaps=metrics["priority_2_gaps"],
        priority_3_gaps=metrics["priority_3_gaps"],
        estimated_timeline_months=metrics["estimated_timeline_months"],
        generation_metadata=generation_metadata
    )
