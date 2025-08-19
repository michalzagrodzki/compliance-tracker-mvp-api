import time
from fastapi import APIRouter, Request, HTTPException

from auth.decorators import ValidatedUser, authorize
from services.audit_log import create_audit_log
from services.executive_summary import generate_executive_summary
from services.schemas import ExecutiveSummaryRequest, ExecutiveSummaryResponse, RiskLevel
from config.config import settings

router = APIRouter(prefix="/audit-reports/executive-summary", tags=["Audit Reports"])


@router.post("",
    response_model=ExecutiveSummaryResponse,
    summary="Generate executive summary from audit report and compliance gaps",
    description="Creates a professional executive summary using OpenAI API based on audit report data and identified compliance gaps. Returns formatted markdown suitable for executive presentation."
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def create_executive_summary(
    req: ExecutiveSummaryRequest,
    request: Request,
    current_user: ValidatedUser = None
) -> ExecutiveSummaryResponse:
    start_time = time.time()

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    if req.audit_report.audit_session_id != req.compliance_gaps[0].audit_session_id if req.compliance_gaps else True:
        if req.compliance_gaps:
            mismatched_gaps = [
                gap for gap in req.compliance_gaps 
                if gap.audit_session_id != req.audit_report.audit_session_id
            ]
            if mismatched_gaps:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Found {len(mismatched_gaps)} compliance gaps with mismatched audit_session_id"
                )

    audit_report_dict = req.audit_report.model_dump()
    compliance_gaps_list = [gap.model_dump() for gap in req.compliance_gaps]

    try:
        executive_summary = generate_executive_summary(
            audit_report=audit_report_dict,
            compliance_gaps=compliance_gaps_list,
            summary_type=req.summary_type.value,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail="An unexpected error occurred while generating the executive summary"
        )
    
    end_time = time.time()
    response_time_ms = int((end_time - start_time) * 1000)

    total_gaps = len(req.compliance_gaps)
    high_risk_gaps = len([gap for gap in req.compliance_gaps if gap.risk_level == RiskLevel.HIGH])
    medium_risk_gaps = len([gap for gap in req.compliance_gaps if gap.risk_level == RiskLevel.MEDIUM])
    low_risk_gaps = len([gap for gap in req.compliance_gaps if gap.risk_level == RiskLevel.LOW])
    regulatory_gaps = len([gap for gap in req.compliance_gaps if gap.regulatory_requirement])
    potential_financial_impact = sum(
        float(gap.potential_fine_amount) if gap.potential_fine_amount is not None else 0.0
        for gap in req.compliance_gaps
    )

    generation_metadata = {
        "generation_time_ms": response_time_ms,
        "summary_type": req.summary_type.value,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "openai_model": settings.openai_model,
        "audit_report_title": req.audit_report.report_title,
        "target_audience": req.audit_report.target_audience,
        "confidentiality_level": req.audit_report.confidentiality_level,
        "documents_reviewed": len(req.audit_report.document_ids),
        "chat_sessions": len(req.audit_report.chat_history_ids),
        "pdf_sources": len(req.audit_report.pdf_ingestion_ids),
        "average_confidence_score": (
            sum(gap.confidence_score for gap in req.compliance_gaps) / len(req.compliance_gaps)
            if req.compliance_gaps else 0.0
        ),
        "average_false_positive_likelihood": (
            sum(gap.false_positive_likelihood for gap in req.compliance_gaps) / len(req.compliance_gaps)
            if req.compliance_gaps else 0.0
        )
    }

    # Create audit log
    create_audit_log(
        object_type="audit_session",
        user_id=current_user.id,
        object_id=req.audit_report.audit_session_id,
        action="create",
        compliance_domain=req.audit_report.compliance_domain,
        audit_session_id=req.audit_report.audit_session_id,
        risk_level="high",
        details={"audit report title": req.audit_report.report_title, "summary type": "executive summary"},
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    return ExecutiveSummaryResponse(
        executive_summary=executive_summary,
        audit_session_id=req.audit_report.audit_session_id,
        compliance_domain=req.audit_report.compliance_domain,
        total_gaps=total_gaps,
        high_risk_gaps=high_risk_gaps,
        medium_risk_gaps=medium_risk_gaps,
        low_risk_gaps=low_risk_gaps,
        regulatory_gaps=regulatory_gaps,
        potential_financial_impact=potential_financial_impact,
        generation_metadata=generation_metadata
    )