from datetime import datetime, timezone
import json
from typing import Any, List, Dict, Optional
from fastapi import APIRouter, HTTPException, Query, Path, Body, Request, Header, Response, status
import uuid

from slowapi import Limiter
from slowapi.util import get_remote_address

from auth.decorators import ValidatedUser, authorize
from security.endpoint_validator import compute_fingerprint, require_idempotency, store_idempotency, normalize_user_agent, ensure_json_request
from security.input_validator import InputValidator, SecurityError
from dependencies import AuditReportServiceDep
from dependencies import AuditSessionServiceDep
from dependencies import AuditLogServiceDep
from entities.audit_log import AuditLogCreate
from common.exceptions import ValidationException, AuthorizationException, BusinessLogicException
from common.logging import get_logger
from services.audit_report_versions import (
    create_audit_report_version,
    serialize_uuids,
)

from entities.audit_session import AuditSessionUpdate
from services.schemas import (
    AuditReportCreate,
    AuditReportUpdate,
    GeneratedRecommendationResponse,
    GeneratedActionItemResponse,
)

# --- constants / helpers ---
IDEMPOTENCY_TTL_SECONDS = 24 * 3600
ALLOWED_FIELDS_CREATE = {
    # keep this list tightly scoped to what clients may set (OWASP API3:2023)
    "report_title",
    "report_type", 
    "compliance_domain",
    "target_audience",
    "confidentiality_level",
    "audit_session_id",
    "compliance_gap_ids",
    "document_ids",
    "pdf_ingestion_ids",
    "include_technical_details",
    "include_source_citations",
    "include_confidence_scores"
}

logger = get_logger(__name__)
router = APIRouter(prefix="/audit-reports", tags=["Audit Reports"])
limiter = Limiter(key_func=get_remote_address)

@router.get("/compliance-domain",
    summary="List audit reports by compliance domains linked to user",
    description="List all audit reports by compliance domains linked to user",
    response_model=List[Dict[str, Any]]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_all_audit_reports(
    audit_report_service: AuditReportServiceDep = None,
    audit_log_service: AuditLogServiceDep = None,
    current_user: ValidatedUser = None
) -> List[Dict[str, Any]]:
    user_compliance_domains = getattr(current_user, 'compliance_domains', [])
    
    if not user_compliance_domains:
        raise HTTPException(
            status_code=403, 
            detail="Access denied."
        )
    # Best-effort audit log via service (ignore failures for non-admin users)
    try:
        audit_log = AuditLogCreate(
            object_type="audit_report",
            object_id=str(current_user.id),
            action="view",
            user_id=str(current_user.id),
            compliance_domain=current_user.compliance_domains[0],
            audit_session_id=None,
            risk_level="high",
            details={},
            ip_address=None,
            user_agent=None,
            tags=[],
        )
        await audit_log_service.create_audit_log(audit_log, str(current_user.id))
    except Exception:
        logger.debug("Audit log creation skipped/failed for get_all_audit_reports", exc_info=True)

    return await audit_report_service.list_reports_by_domains(current_user.id, user_compliance_domains)

@router.get("/{report_id}",
    summary="Get audit report by ID",
    description="Fetches a specific audit report by its ID.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def get_audit_report(
    report_id: str = Path(..., description="Audit report UUID"),
    audit_report_service: AuditReportServiceDep = None,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    return await audit_report_service.get_report_by_id(report_id, current_user.id)

@router.post("",
    summary="Create new audit report",
    description="Creates a new audit report with the provided details and comprehensive security controls.",
    response_model=Dict[str, Any],
    status_code=201
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def create_new_audit_report(
    request: Request,
    response: Response,
    report_data: AuditReportCreate = Body(..., description="Audit report data"),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key", convert_underscores=False),
    audit_report_service: AuditReportServiceDep = None,
    audit_session_service: AuditSessionServiceDep = None,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    """Create new audit report with enhanced security controls."""
    # NIST CSF 2.0 PR.DS-05: Data-at-rest protection, NIST SP 800-53 SI-10: Input validation
    ensure_json_request(request)
    ua = normalize_user_agent(request.headers.get("user-agent"))
    
    try:
        # Extract client information for audit trail (NIST CSF 2.0 DE.AE-03: Event data aggregation)
        ip_address = request.client.host if request.client else None
        
        # Convert request data to dict for processing and input validation
        if hasattr(report_data, "model_dump"):
            payload = report_data.model_dump()
        elif hasattr(report_data, "dict"):
            payload = report_data.dict()
        else:
            payload = dict(report_data)
        
        # Filter payload to only allowed create fields (OWASP API3:2023 - Broken Object Property Level Authorization)
        filtered_payload = {k: v for k, v in payload.items() if k in ALLOWED_FIELDS_CREATE}
        
        # Input validation and sanitization (NIST CSF 2.0 PR.DS-02: Data-in-transit protection)
        try:
            if "report_title" in filtered_payload and filtered_payload["report_title"]:
                filtered_payload["report_title"] = InputValidator.sanitize_text(filtered_payload["report_title"], 200)
            
            if "compliance_domain" in filtered_payload and filtered_payload["compliance_domain"]:
                filtered_payload["compliance_domain"] = InputValidator.validate_compliance_domain(filtered_payload["compliance_domain"])
            
            # Validate UUID format for audit_session_id
            if "audit_session_id" in filtered_payload and filtered_payload["audit_session_id"]:
                import uuid
                try:
                    uuid.UUID(str(filtered_payload["audit_session_id"]))
                except ValueError:
                    raise SecurityError("Invalid audit_session_id format - must be UUID")
                    
        except SecurityError as e:
            logger.warning(f"Input validation failed for audit report creation: {e}", extra={
                "user_id": current_user.id,
                "ip_address": ip_address,
                "user_agent": ua
            })
            raise HTTPException(status_code=400, detail=str(e))
        
        # Validate required fields are present
        if not filtered_payload.get("report_title") or not filtered_payload.get("audit_session_id"):
            raise HTTPException(
                status_code=400,
                detail="report_title and audit_session_id are required"
            )
        
        # Idempotency protection for create operations (NIST CSF 2.0 PR.DS-01: Data-at-rest protection)
        fingerprint = compute_fingerprint(filtered_payload | {"user_id": current_user.id})
        repo = request.app.state.idempotency_repo
        cached = require_idempotency(repo, idempotency_key, fingerprint)
        
        if cached:
            response.headers["Location"] = cached.get("location", "")
            return cached["body"]
        
        # Apply user context and access control (NIST CSF 2.0 PR.AC-01: Identity management)
        report_dict = filtered_payload.copy()
        if current_user.role != "admin" and str(report_dict.get("user_id")) != str(current_user.id):
            report_dict["user_id"] = current_user.id

        for field in ["user_id", "audit_session_id"]:
            if field in report_dict and report_dict[field]:
                report_dict[field] = str(report_dict[field])

        for field in ["compliance_gap_ids", "document_ids", "pdf_ingestion_ids"]:
            if field in report_dict and report_dict[field]:
                report_dict[field] = [str(uuid_val) for uuid_val in report_dict[field]]

        try:
            created_report = await audit_report_service.create_report(report_dict, str(current_user.id))
        except Exception as e:
            logger.error(f"Error creating audit report: {str(e)}", extra={
                "user_id": current_user.id,
                "ip_address": ip_address,
                "user_agent": ua,
                "audit_session_id": report_dict.get("audit_session_id")
            })
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
            logger.error(f"Error creating audit report version: {str(e)}", extra={
                "user_id": current_user.id,
                "audit_report_id": created_report["id"]
            })
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error creating audit report version: {str(e)}"
            )

        try:
            await audit_session_service.update_session(
                session_id=str(report_data.audit_session_id),
                update_data=AuditSessionUpdate(audit_report=str(created_report["id"])),
                user_id=current_user.id,
                ip_address=ip_address,
                user_agent=ua
            )
        except Exception as e:
            logger.error(f"Error updating audit session: {str(e)}", extra={
                "user_id": current_user.id,
                "audit_session_id": report_data.audit_session_id,
                "audit_report_id": created_report["id"]
            })
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error updating audit session: {str(e)}"
            )

        # Security audit logging (NIST CSF 2.0 DE.AE-03: Event data aggregation)
        create_audit_log(
            object_type="audit_report",
            user_id=current_user.id,
            object_id=created_report["id"],
            action="create",
            compliance_domain=report_dict.get("compliance_domain"),
            audit_session_id=report_dict.get("audit_session_id"),
            risk_level="high",
            details={
                "report_title": report_dict.get("report_title"),
                "report_type": report_dict.get("report_type"),
                "confidentiality_level": report_dict.get("confidentiality_level"),
                "method": "api_endpoint"
            },
            ip_address=ip_address,
            user_agent=ua
        )

        # Prepare structured response with location header
        location = f"/v1/audit-reports/{created_report['id']}"
        body = {
            "data": created_report,
            "meta": {
                "message": "Audit report created successfully",
                "compliance_domain": report_dict.get("compliance_domain"),
                "confidentiality_level": report_dict.get("confidentiality_level")
            }
        }

        # Store idempotency result (NIST CSF 2.0 PR.DS-01: Data-at-rest protection)
        store_idempotency(
            repo, idempotency_key, fingerprint,
            {"body": body, "location": location}, IDEMPOTENCY_TTL_SECONDS
        )
        
        response.headers["Location"] = location
        return body

    except ValidationException as e:
        raise HTTPException(status_code=400, detail=e.detail)
    except AuthorizationException as e:
        raise HTTPException(status_code=403, detail=e.detail)
    except BusinessLogicException as e:
        raise HTTPException(status_code=500, detail=e.detail)
    except HTTPException:
        # Already handled above, just propagate
        raise
    except Exception as e:
        # Fallback for any unexpected error with security logging
        logger.error(f"Unexpected error in audit report creation: {str(e)}", extra={
            "user_id": current_user.id if current_user else None,
            "ip_address": ip_address,
            "user_agent": ua,
            "error_type": type(e).__name__
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error occurred during audit report creation"
        )

@router.patch("/{report_id}",
    summary="Update audit report",
    description="Updates an existing audit report with new information.",
    response_model=Dict[str, Any]
)
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def update_existing_audit_report(
    report_id: str = Path(..., description="Audit report UUID"),
    update_data: AuditReportUpdate = Body(..., description="Fields to update"),
    change_description: str = Body(..., description="Description of changes made", embed=True),
    audit_report_service: AuditReportServiceDep = None,
    current_user: ValidatedUser = None
) -> Dict[str, Any]:
    update_dict = update_data.model_dump(exclude_unset=True)

    # Convert UUID fields to strings to avoid JSON serialization errors
    for field in ["user_id", "audit_session_id"]:
        if field in update_dict and update_dict[field]:
            update_dict[field] = str(update_dict[field])

    for field in ["compliance_gap_ids", "document_ids", "pdf_ingestion_ids"]:
        if field in update_dict and update_dict[field]:
            update_dict[field] = [str(uuid_val) for uuid_val in update_dict[field]]

    # Serialize array fields to JSON strings for database storage
    for field in ["recommendations", "action_items"]:
        if field in update_dict and update_dict[field] is not None:
            if isinstance(update_dict[field], (list, dict)):
                update_dict[field] = json.dumps(update_dict[field])
            elif isinstance(update_dict[field], str):
                # If it's already a string, try to parse and re-serialize to ensure valid JSON
                try:
                    parsed = json.loads(update_dict[field])
                    update_dict[field] = json.dumps(parsed)
                except (json.JSONDecodeError, ValueError):
                    # If it's not valid JSON, treat as plain string and wrap in array
                    update_dict[field] = json.dumps([update_dict[field]])

    updated_report = await audit_report_service.update_report(report_id, update_dict, str(current_user.id))

    if update_dict:
        serialized_report = serialize_uuids(updated_report)
        create_audit_report_version(
            audit_report_id=report_id,
            changed_by=str(current_user.id),
            change_description=change_description,
            change_type="draft_update",
            report_snapshot=serialized_report
        )
    
    return updated_report

@router.post("/recommendation/{audit_session_id}",
    summary="Create recommendations for audit session",
    description="Generate recommendations for a specific audit session.",
    response_model=GeneratedRecommendationResponse,
    status_code=201
)
@limiter.limit("10/minute")
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def create_recommendations(
    request: Request,
    audit_session_id: str = Path(..., description="Audit session UUID"),
    audit_report_service: AuditReportServiceDep = None,
    audit_log_service: AuditLogServiceDep = None,
    current_user: ValidatedUser = None
) -> GeneratedRecommendationResponse:
    """Create recommendations for an audit session."""
    try:
        try:
            uuid.UUID(str(audit_session_id))
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid audit_session_id format - must be UUID"
            )
        
        # Generate recommendations using the service
        result = await audit_report_service.generate_recommendations(audit_session_id)
        
        # Create audit log (best-effort)
        try:
            audit_log = AuditLogCreate(
                object_type="audit_report",
                object_id=str(audit_session_id),
                action="generate",
                user_id=str(current_user.id),
                compliance_domain=None,
                audit_session_id=str(audit_session_id),
                risk_level="medium",
                details={
                    "method": "api_endpoint",
                    "recommendations_length": len(result['recommendations']),
                    "gaps_analyzed": result.get('gaps_analyzed', 0),
                },
                ip_address=None,
                user_agent=None,
                tags=[],
            )
            await audit_log_service.create_audit_log(audit_log, str(current_user.id))
        except Exception:
            logger.debug("Audit log creation skipped/failed for create_recommendations", exc_info=True)
        
        return GeneratedRecommendationResponse(
            message="Recommendations generated successfully",
            audit_session_id=audit_session_id,
            recommendations=result['recommendations'],
            generated_at=datetime.now(timezone.utc),
            generated_by=str(current_user.id),
            gaps_analyzed=result.get('gaps_analyzed'),
            chat_sessions_analyzed=result.get('chat_sessions_analyzed'),
            high_risk_gaps=result.get('high_risk_gaps')
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating recommendations: {str(e)}", extra={
            "user_id": current_user.id,
            "audit_session_id": audit_session_id
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error occurred during recommendations creation"
        )

@router.post("/action-items/{audit_session_id}",
    summary="Create action items for audit session",
    description="Generate action items for a specific audit session.",
    response_model=GeneratedActionItemResponse,
    status_code=201
)
@limiter.limit("10/minute")
@authorize(allowed_roles=["admin", "compliance_officer"], check_active=True)
async def create_action_items(
    request: Request,
    audit_session_id: str = Path(..., description="Audit session UUID"),
    audit_report_service: AuditReportServiceDep = None,
    audit_log_service: AuditLogServiceDep = None,
    current_user: ValidatedUser = None
) -> GeneratedActionItemResponse:
    """Create action items for an audit session."""
    try:
        try:
            uuid.UUID(str(audit_session_id))
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid audit_session_id format - must be UUID"
            )
        
        # Generate action items using the service
        result = await audit_report_service.generate_action_items(audit_session_id)
        
        # Create audit log (best-effort)
        try:
            audit_log = AuditLogCreate(
                object_type="audit_report",
                object_id=str(audit_session_id),
                action="generate",
                user_id=str(current_user.id),
                compliance_domain=None,
                audit_session_id=str(audit_session_id),
                risk_level="medium",
                details={
                    "method": "api_endpoint",
                    "action_items_length": len(result['action_items']),
                    "gaps_analyzed": result.get('gaps_analyzed', 0),
                },
                ip_address=None,
                user_agent=None,
                tags=[],
            )
            await audit_log_service.create_audit_log(audit_log, str(current_user.id))
        except Exception:
            logger.debug("Audit log creation skipped/failed for create_action_items", exc_info=True)
        
        return GeneratedActionItemResponse(
            message="Action items generated successfully",
            audit_session_id=audit_session_id,
            action_items=result['action_items'],
            generated_at=datetime.now(timezone.utc),
            generated_by=str(current_user.id),
            gaps_analyzed=result.get('gaps_analyzed'),
            chat_sessions_analyzed=result.get('chat_sessions_analyzed'),
            regulatory_gaps=result.get('regulatory_gaps'),
            critical_high_risk_gaps=result.get('critical_high_risk_gaps')
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating action items: {str(e)}", extra={
            "user_id": current_user.id,
            "audit_session_id": audit_session_id
        })
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error occurred during action items creation"
        )
