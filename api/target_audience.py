import time
from fastapi import APIRouter, Request, HTTPException
from slowapi import Limiter
from slowapi.util import get_remote_address

from auth.decorators import ValidatedUser, authorize
from dependencies import AuditLogServiceDep
from entities.audit_log import AuditLogCreate
from services.target_audience_summary import generate_target_audience_summary, get_audience_context
from services.schemas import ExecutiveSummaryRequest, TargetAudienceSummaryResponse
from config.config import settings

router = APIRouter(prefix="/audit-reports/target-audience", tags=["Audit Reports"])
limiter = Limiter(key_func=get_remote_address)


@router.post("",
    response_model=TargetAudienceSummaryResponse,
    summary="Generate target audience summary from audit report and compliance gaps",
    description="Creates a professional target audience-specific summary using OpenAI API based on audit report data and identified compliance gaps. Returns formatted markdown tailored to the specific audience needs (executives, compliance_team, auditors, regulators, board)."
)
@limiter.limit("10/minute")
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def create_target_audience_summary(
    request_data: ExecutiveSummaryRequest,
    request: Request,
    audit_log_service: AuditLogServiceDep = None,
    current_user: ValidatedUser = None
) -> TargetAudienceSummaryResponse:
    start_time = time.time()

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    # Validate that compliance gaps match the audit session
    if request_data.compliance_gaps and request_data.audit_report.audit_session_id != request_data.compliance_gaps[0].audit_session_id:
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
    compliance_gaps_list = request_data.compliance_gaps

    try:
        target_audience_summary = generate_target_audience_summary(
            audit_report=audit_report_dict,
            compliance_gaps=compliance_gaps_list,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail="An unexpected error occurred while generating the target audience summary"
        )
    
    end_time = time.time()
    response_time_ms = int((end_time - start_time) * 1000)

    # Calculate summary statistics
    total_gaps = len(request_data.compliance_gaps)
    high_risk_gaps = len([gap for gap in request_data.compliance_gaps if gap.risk_level == 'high'])
    medium_risk_gaps = len([gap for gap in request_data.compliance_gaps if gap.risk_level == 'medium'])
    low_risk_gaps = len([gap for gap in request_data.compliance_gaps if gap.risk_level == 'low'])
    regulatory_gaps = len([gap for gap in request_data.compliance_gaps if gap.regulatory_requirement])
    
    gaps_with_recommendations = len([
        gap for gap in request_data.compliance_gaps 
        if gap.recommendation_text and gap.recommendation_text.strip()
    ])
    
    potential_financial_impact = sum(
        float(gap.potential_fine_amount) if gap.potential_fine_amount is not None else 0.0
        for gap in request_data.compliance_gaps
    )

    # Get audience-specific focus areas
    audience_context = get_audience_context(request_data.audit_report.target_audience)
    audience_focus_areas = audience_context.get('focus', '').split(', ')

    generation_metadata = {
        "generation_time_ms": response_time_ms,
        "target_audience": request_data.audit_report.target_audience,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "openai_model": settings.openai_model,
        "audit_report_title": request_data.audit_report.report_title,
        "confidentiality_level": request_data.audit_report.confidentiality_level,
        "documents_reviewed": len(request_data.audit_report.document_ids or []),
        "chat_sessions": len(request_data.audit_report.chat_history_ids or []),
        "pdf_sources": len(request_data.audit_report.pdf_ingestion_ids or []),
        "audience_tone": audience_context.get('tone', 'professional'),
        "audience_format": audience_context.get('format', 'standard'),
        "audience_language": audience_context.get('language', 'professional'),
        "average_confidence_score": (
            sum(gap.confidence_score for gap in request_data.compliance_gaps if gap.confidence_score) / 
            len([gap for gap in request_data.compliance_gaps if gap.confidence_score])
            if any(gap.confidence_score for gap in request_data.compliance_gaps) else 0.0
        ),
        "average_false_positive_likelihood": (
            sum(gap.false_positive_likelihood for gap in request_data.compliance_gaps if gap.false_positive_likelihood) / 
            len([gap for gap in request_data.compliance_gaps if gap.false_positive_likelihood])
            if any(gap.false_positive_likelihood for gap in request_data.compliance_gaps) else 0.0
        )
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
                "summary type": "target audience summary",
            },
            ip_address=ip_address,
            user_agent=user_agent,
            tags=[],
        )
        await audit_log_service.create_audit_log(audit_log, str(current_user.id))
    except Exception:
        pass
    
    return TargetAudienceSummaryResponse(
        target_audience_summary=target_audience_summary,
        audit_session_id=request_data.audit_report.audit_session_id,
        compliance_domain=request_data.audit_report.compliance_domain,
        target_audience=request_data.audit_report.target_audience,
        total_gaps=total_gaps,
        high_risk_gaps=high_risk_gaps,
        medium_risk_gaps=medium_risk_gaps,
        low_risk_gaps=low_risk_gaps,
        regulatory_gaps=regulatory_gaps,
        gaps_with_recommendations=gaps_with_recommendations,
        potential_financial_impact=potential_financial_impact,
        audience_focus_areas=audience_focus_areas,
        generation_metadata=generation_metadata
    )
