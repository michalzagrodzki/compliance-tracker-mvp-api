from typing import Set

# fields the server always controls (never from client)
SERVER_CONTROLLED_FIELDS: Set[str] = {
    "user_id", "ip_address", "user_agent",
}

# Allowed fields for RAG query endpoints
ALLOWED_QUERY_FIELDS: Set[str] = {
    "question",
    "conversation_id",
    "audit_session_id",
    "match_threshold",
    "match_count",
    "compliance_domain",
    "document_versions",
    "document_tags",
}

