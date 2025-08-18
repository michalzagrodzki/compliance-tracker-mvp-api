from datetime import datetime, timezone
import logging
from typing import Any, List, Dict, Optional
from fastapi import APIRouter, HTTPException, Query, Path, Body, Request, Query,status

from auth.decorators import ValidatedUser, authorize
from services.audit_log import create_audit_log
from services.audit_reports import (
    generate_audit_report_from_session,
    list_audit_reports,
    list_audit_reports_by_compliance_domains,
    list_audit_reports_by_compliance_domain,
    get_audit_report_by_id,
    create_audit_report,
    update_audit_report,
    delete_audit_report,
    get_audit_report_statistics,
)
from services.audit_report_versions import (
    compare_audit_report_versions,
    create_audit_report_version,
    get_latest_audit_report_version,
    get_audit_report_version_by_number,
    list_audit_report_versions,
    serialize_uuids,
)
from services.audit_report_distributions import (
    bulk_distribute_report,
    cleanup_expired_distributions,
    delete_distribution,
    get_audit_report_distribution_by_id,
    get_distributions_by_report_id,
    list_audit_report_distributions,
    create_audit_report_distribution,
)
from services.audit_sessions import update_audit_session
from services.schemas import (
    AuditReportCreate,
    AuditReportUpdate,
    AuditReportGenerateRequest,
    AuditReportStatusUpdate,
    AuditReportSearchRequest,
    AuditReportDistributionCreate,
)

router = APIRouter(prefix="/audit-reports", tags=["Audit Reports"])

@router.get("",
    summary="List all audit reports with pagination",
    description="Fetches paginated audit reports from the database.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_all_audit_reports(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    report_type: Optional[str] = Query(None, description="Filter by report type"),
    report_status: Optional[str] = Query(None, description="Filter by report status"),
    user_id: Optional[str] = Query(None, description="Filter by creator user"),
    audit_session_id: Optional[str] = Query(None, description="Filter by audit session"),
    target_audience: Optional[str] = Query(None, description="Filter by target audience"),
    confidentiality_level: Optional[str] = Query(None, description="Filter by confidentiality level"),
    generated_after: Optional[datetime] = Query(None, description="Filter by generation date (after)"),
    generated_before: Optional[datetime] = Query(None, description="Filter by generation date (before)"),
) -> List[Dict[str, Any]]:
    return list_audit_reports(
        skip=skip,
        limit=limit,
        compliance_domain=compliance_domain,
        report_type=report_type,
        report_status=report_status,
        user_id=user_id,
        audit_session_id=audit_session_id,
        target_audience=target_audience,
        confidentiality_level=confidentiality_level,
        generated_after=generated_after,
        generated_before=generated_before
    )

@router.get("/compliance-domain",
    summary="List audit reports by compliance domains linked to user",
    description="List all audit reports by compliance domains linked to user",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_all_audit_reports(
    current_user: ValidatedUser = None
) -> List[Dict[str, Any]]:
    user_compliance_domains = getattr(current_user, 'compliance_domains', [])
    
    if not user_compliance_domains:
        raise HTTPException(
            status_code=403, 
            detail="Access denied."
        )
    create_audit_log(
        object_type="audit_report",
        user_id=current_user.id,
        object_id=current_user.id,
        action="view",
        compliance_domain=current_user.compliance_domains[0],
        audit_session_id=None,
        risk_level="high",
        details={},
        ip_address=None,
        user_agent=None
    )

    return list_audit_reports_by_compliance_domains(user_compliance_domains)

@router.get("/compliance-domain/{compliance_domain_code}",
    summary="List audit reports by compliance domain",
    description="Get audit reports for a specific compliance domain",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin"], check_active=True)
def get_all_audit_reports(
    compliance_domain_code: str = Path(..., description="compliance_domain_code"),
) -> List[Dict[str, Any]]:
    return list_audit_reports_by_compliance_domain(compliance_domain_code)

@router.get("/{report_id}",
    summary="Get audit report by ID",
    description="Fetches a specific audit report by its ID.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_report(
    report_id: str = Path(..., description="Audit report UUID"),
) -> Dict[str, Any]:
    return get_audit_report_by_id(report_id)

@router.post("",
    summary="Create new audit report",
    description="Creates a new audit report with the provided details.",
    response_model=Dict[str, Any],
    status_code=201
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def create_new_audit_report(
    report_data: AuditReportCreate = Body(..., description="Audit report data"),
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    try:
        report_dict = report_data.model_dump()

        if current_user.role != "admin" and str(report_dict.get("user_id")) != str(current_user.id):
            report_dict["user_id"] = current_user.id

        for field in ["user_id", "audit_session_id"]:
            if field in report_dict and report_dict[field]:
                report_dict[field] = str(report_dict[field])

        for field in ["compliance_gap_ids", "document_ids", "pdf_ingestion_ids"]:
            if field in report_dict and report_dict[field]:
                report_dict[field] = [str(uuid_val) for uuid_val in report_dict[field]]

        try:
            created_report = create_audit_report(report_dict)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error creating audit report: {str(e)}"
            )

        serialized_report = serialize_uuids(created_report)

        try:
            create_audit_report_version(
                audit_report_id=created_report["id"],
                changed_by=str(current_user.id),
                change_description="Initial report creation",
                change_type="draft_update",
                report_snapshot=serialized_report
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error creating audit report version: {str(e)}"
            )

        try:
            update_audit_session(
                session_id=report_data.audit_session_id,
                audit_report=created_report["id"]
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error updating audit session: {str(e)}"
            )

        return created_report

    except HTTPException:
        # Already handled above, just propagate
        raise
    except Exception as e:
        # Fallback for any unexpected error
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error: {str(e)}"
        )

@router.post("/generate",
    summary="Generate audit report",
    description="Generate a comprehensive audit report based on session data.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def generate_audit_report(
    generate_request: AuditReportGenerateRequest = Body(..., description="Report generation parameters"),
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    generation_options = {
        "include_technical_details": generate_request.include_technical_details,
        "include_source_citations": generate_request.include_source_citations,
        "include_confidence_scores": generate_request.include_confidence_scores,
        "target_audience": generate_request.target_audience,
        "confidentiality_level": generate_request.confidentiality_level
    }
    
    report = generate_audit_report_from_session(
        audit_session_id=str(generate_request.audit_session_id),
        user_id=str(current_user.id),
        report_title=generate_request.report_title,
        report_type=generate_request.report_type,
        **generation_options
    )

    if generate_request.auto_distribute and generate_request.distribution_list:
        try:
            bulk_distribute_report(
                audit_report_id=report["id"],
                recipients=generate_request.distribution_list,
                distribution_method="email",
                distribution_format="pdf",
                distributed_by=str(current_user.id)
            )
        except Exception as e:
            logging.warning(f"Auto-distribution failed: {e}")
    
    return report

@router.patch("/{report_id}",
    summary="Update audit report",
    description="Updates an existing audit report with new information.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def update_existing_audit_report(
    report_id: str = Path(..., description="Audit report UUID"),
    update_data: AuditReportUpdate = Body(..., description="Fields to update"),
    change_description: str = Body(..., description="Description of changes made", embed=True),
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    update_dict = update_data.model_dump(exclude_unset=True)

    updated_report = update_audit_report(report_id, update_dict)

    if update_dict:
        create_audit_report_version(
            audit_report_id=report_id,
            changed_by=str(current_user.id),
            change_description=change_description,
            change_type="draft_update",
            report_snapshot=updated_report
        )
    
    return updated_report

@router.put("/{report_id}/status",
    summary="Update audit report status",
    description="Updates the status of an audit report.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def update_audit_report_status(
    report_id: str = Path(..., description="Audit report UUID"),
    status_update: AuditReportStatusUpdate = Body(..., description="New status data"),
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    update_data = {"report_status": status_update.new_status}

    if status_update.new_status == "approved":
        update_data["approved_by"] = str(current_user.id)
    elif status_update.new_status == "finalized":
        update_data["report_finalized_at"] = datetime.now(timezone.utc).isoformat()
    
    updated_report = update_audit_report(report_id, update_data)

    create_audit_report_version(
        audit_report_id=report_id,
        changed_by=str(current_user.id),
        change_description=f"Status changed to {status_update.new_status}" + (f": {status_update.notes}" if status_update.notes else ""),
        change_type="approval_change",
        report_snapshot=updated_report
    )
    
    return updated_report

@router.delete("/{report_id}",
    summary="Delete audit report",
    description="Deletes an audit report and associated data.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def delete_existing_audit_report(
    report_id: str = Path(..., description="Audit report UUID"),
    hard_delete: bool = Query(False, description="If true, permanently delete (not recommended)"),
) -> Dict[str, Any]:
    return delete_audit_report(report_id, soft_delete=not hard_delete)

@router.post("/search",
    summary="Search audit reports",
    description="Search audit reports using various criteria.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def search_audit_reports_endpoint(
    search_request: AuditReportSearchRequest,
    current_user: ValidatedUser = None
) -> List[Dict[str, Any]]:
    return list_audit_reports(
        skip=search_request.skip,
        limit=search_request.limit,
        compliance_domain=search_request.compliance_domain,
        report_type=search_request.report_type,
        report_status=search_request.report_status,
        user_id=str(search_request.user_id) if search_request.user_id else None,
        audit_session_id=str(search_request.audit_session_id) if search_request.audit_session_id else None,
        target_audience=search_request.target_audience,
        confidentiality_level=search_request.confidentiality_level,
        generated_after=search_request.generated_after,
        generated_before=search_request.generated_before
    )

@router.get("/statistics",
    summary="Get audit report statistics",
    description="Get aggregated statistics about audit reports.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_report_statistics_endpoint(
    compliance_domain: Optional[str] = Query(None, description="Filter by compliance domain"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    start_date: Optional[datetime] = Query(None, description="Filter reports generated after this date"),
    end_date: Optional[datetime] = Query(None, description="Filter reports generated before this date"),
) -> Dict[str, Any]:
    return get_audit_report_statistics(
        compliance_domain=compliance_domain,
        user_id=user_id,
        start_date=start_date,
        end_date=end_date
    )

# Audit Report Versions
@router.get("/{report_id}/versions",
    summary="Get audit report versions",
    description="Get all versions of a specific audit report.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_report_versions(
    report_id: str = Path(..., description="Audit report UUID"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
) -> List[Dict[str, Any]]:
    return list_audit_report_versions(report_id, skip, limit)

@router.get("/{report_id}/versions/latest",
    summary="Get latest audit report version",
    description="Get the latest version of a specific audit report.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_latest_audit_report_version_endpoint(
    report_id: str,
) -> Dict[str, Any]:
    return get_latest_audit_report_version(report_id)

@router.get("/{report_id}/versions/{version_number}",
    summary="Get audit report version by number",
    description="Get a specific version of an audit report by version number.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_report_version_by_number_endpoint(
    report_id: str,
    version_number: int,
) -> Dict[str, Any]:
    return get_audit_report_version_by_number(report_id, version_number)

@router.get("/{report_id}/versions/compare/{version1}/{version2}",
    summary="Compare audit report versions",
    description="Compare two versions of an audit report",
    response_model=Dict[str, Any],
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def compare_audit_report_versions_endpoint(
    report_id: str = Path(..., description="Audit report UUID"),
    version1: int = Path(..., description="First version number", ge=1),
    version2: int = Path(..., description="Second version number", ge=1),
) -> Dict[str, Any]:
    return compare_audit_report_versions(report_id, version1, version2)

# Audit Report Distributions
@router.get("/distributions",
    summary="List all audit report distributions",
    description="Get all audit report distributions with pagination.",
    response_model=List[Dict[str, Any]]
)
def get_all_audit_report_distributions(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    audit_report_id: Optional[str] = Query(None, description="Filter by audit report ID"),
    distributed_to: Optional[str] = Query(None, description="Filter by recipient"),
    distribution_method: Optional[str] = Query(None, description="Filter by distribution method"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
) -> List[Dict[str, Any]]:
    return list_audit_report_distributions(
        audit_report_id=audit_report_id,
        distributed_to=distributed_to,
        distribution_method=distribution_method,
        is_active=is_active,
        skip=skip,
        limit=limit
    )

@router.get("/{report_id}/distributions",
    summary="Get audit report distributions",
    description="Get distributions for a specific audit report.",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_report_distributions(
    report_id: str = Path(..., description="Audit report UUID"),
) -> List[Dict[str, Any]]:
    return get_distributions_by_report_id(report_id)


@router.post("/{report_id}/distribute",
    summary="Distribute audit report",
    description="Create a new distribution for an audit report.",
    response_model=Dict[str, Any],
    status_code=201
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def distribute_audit_report(
    report_id: str = Path(..., description="Audit report UUID"),
    distribution_data: AuditReportDistributionCreate = Body(..., description="Distribution details"),
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return create_audit_report_distribution(
        audit_report_id=report_id,
        distributed_to=distribution_data.distributed_to,
        distribution_method=distribution_data.distribution_method,
        distribution_format=distribution_data.distribution_format,
        distributed_by=str(current_user.id),
        external_reference=distribution_data.external_reference,
        expiry_date=distribution_data.expiry_date
    )

@router.get("/audit-report-distributions/{distribution_id}",
    summary="Get distribution by ID",
    description="Get detailed information about a specific distribution",
    response_model=Dict[str, Any],
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def get_audit_report_distributions(
    report_id: str = Path(..., description="Audit report UUID"),
) -> List[Dict[str, Any]]:
    return get_distributions_by_report_id(report_id)

@router.delete("/audit-report-distributions/{distribution_id}",
    summary="Delete distribution",
    description="Permanently delete a distribution record",
    response_model=Dict[str, Any],
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
def delete_audit_report_distribution(
    distribution_id: str = Path(..., description="Distribution UUID"),
) -> Dict[str, Any]:
    return delete_distribution(distribution_id)

@router.post("/distributions/cleanup-expired",
    summary="Cleanup expired audit report distributions",
    description="Remove expired audit report distributions.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin"], check_active=True)
def cleanup_expired_audit_report_distributions() -> Dict[str, Any]:
    return cleanup_expired_distributions()