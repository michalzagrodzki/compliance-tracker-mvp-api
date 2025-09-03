from typing import Set

# fields the server always controls (never from client)
SERVER_CONTROLLED_FIELDS: Set[str] = {
    "user_id", "ip_address", "user_agent",
}

# Allowed metadata fields that clients may provide during upload
ALLOWED_FIELDS_UPLOAD: Set[str] = {
    "compliance_domain",
    "document_version",
    "document_tags",
    "document_title",
    "document_author",
}

