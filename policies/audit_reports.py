from typing import Set

# fields the server always controls (never from client)
SERVER_CONTROLLED_FIELDS: Set[str] = {
    "user_id", "ip_address", "user_agent",
}

# Allowed fields for creating an audit report (client-provided)
# Keep tightly scoped to prevent property-level authorization issues
ALLOWED_FIELDS_CREATE: Set[str] = {
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
    "include_confidence_scores",
}

# Allowed fields for updating an audit report (more restrictive than full schema)
# Avoid user_id/audit_session_id and server-maintained timestamps
ALLOWED_FIELDS_UPDATE: Set[str] = {
    # Metadata and status
    "report_title", "report_type", "report_status", "compliance_domain",
    # Content and summaries
    "executive_summary", "control_risk_prioritization", "threat_intelligence_analysis",
    "target_audience_summary", "detailed_findings", "recommendations", "action_items",
    "appendices",
    # References and inputs
    "chat_history_ids", "compliance_gap_ids", "document_ids", "pdf_ingestion_ids",
    # Configuration
    "template_used", "include_technical_details", "include_source_citations",
    "include_confidence_scores", "target_audience",
    # Distribution and approvals
    "generated_by", "reviewed_by", "approved_by", "distributed_to",
    "external_auditor_access", "confidentiality_level",
    # Business and regulatory metrics
    "overall_compliance_rating", "estimated_remediation_cost",
    "estimated_remediation_time_days", "regulatory_risk_score",
    "potential_fine_exposure",
    # File/export metadata
    "report_file_path", "report_file_size", "report_hash", "export_formats",
    # Comparison/trending
    "previous_report_id", "improvement_from_previous", "trending_direction",
    "benchmark_comparison",
    # Integration/automation
    "scheduled_followup_date", "auto_generated", "integration_exports",
    "notification_sent",
    # Regulatory/audit trail
    "audit_trail", "external_audit_reference", "regulatory_submission_date",
    "regulatory_response_received",
}

