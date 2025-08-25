from typing import Set

# fields the server always controls (never from client)
SERVER_CONTROLLED_FIELDS: Set[str] = {
    "user_id", "ip_address", "user_agent",
}

# Per-flow allow-lists (recommended)
ALLOWED_FIELDS_CREATE_FROM_CHAT: Set[str] = {
    "creation_method", "chat_history_id",
    "gap_type", "gap_category", "gap_title", "gap_description",
    "risk_level", "business_impact", "regulatory_requirement", "potential_fine_amount",
    "recommendation_type", "recommendation_text", "recommended_actions", "related_documents",
    "search_terms_used", "iso_control", "assigned_to", "due_date",
    "confidence_score", "false_positive_likelihood",
    "audit_session_id", "compliance_domain", "resolution_notes"
}

ALLOWED_FIELDS_CREATE_DIRECT: Set[str] = {
    "creation_method", "chat_history_id", "pdf_ingestion_id",
    "gap_type", "gap_category", "gap_title", "gap_description",
    "expected_answer_type", "search_terms_used",
    "similarity_threshold_used", "best_match_score",
    "risk_level", "business_impact", "regulatory_requirement", "potential_fine_amount",
    "recommendation_type", "recommendation_text", "recommended_actions", "related_documents",
    "detection_method", "confidence_score", "false_positive_likelihood",
    "session_context", "iso_control", "assigned_to", "due_date",
}

ALLOWED_FIELDS_CREATE = ALLOWED_FIELDS_CREATE_FROM_CHAT | ALLOWED_FIELDS_CREATE_DIRECT
