from typing import Set

# fields the server always controls (never from client)
SERVER_CONTROLLED_FIELDS: Set[str] = {
    "user_id", "ip_address", "user_agent",
}

# Allowed fields for creating an audit session
ALLOWED_FIELDS_CREATE: Set[str] = {
    "session_name",
    "compliance_domain",
}

