from typing import List
from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    # Supabase
    supabase_url: str = Field(..., env="SUPABASE_URL")
    supabase_key: str = Field(..., env="SUPABASE_KEY")
    supabase_table_documents: str = Field("documents", env="SUPABASE_TABLE_DOCUMENTS")
    supabase_table_chat_history: str = Field("chat_history", env="SUPABASE_TABLE_CHAT_HISTORY")
    supabase_table_pdf_ingestion: str = Field("pdf_ingestion", env="SUPABASE_TABLE_PDF_INGESTION")
    supabase_table_compliance_domains: str = Field("compliance_domains", env="SUPABASE_TABLE_COMPLIANCE_DOMAINS")
    supabase_table_compliance_gaps: str = Field("compliance_gaps", env="SUPABASE_TABLE_COMPLIANCE_GAPS")
    supabase_table_audit_sessions: str = Field("audit_sessions", env="SUPABASE_TABLE_AUDIT_SESSIONS")
    supabase_table_users: str = Field("users", env="SUPABASE_TABLE_USERS")
    supabase_table_audit_reports: str = Field("audit_reports", env="SUPABASE_TABLE_AUDIT_REPORTS")
    supabase_table_audit_report_versions: str = Field("audit_report_versions", env="SUPABASE_TABLE_AUDIT_REPORT_VERSIONS")
    supabase_table_audit_report_distributions: str = Field("audit_report_distributions", env="SUPABASE_TABLE_AUDIT_REPORT_DISTRIBUTIONS")
    supabase_table_audit_session_pdf_ingestions: str = Field("audit_session_pdf_ingestions", env="SUPABASE_TABLE_AUDIT_SESSION_PDF_INGESTIONS")
    supabase_table_audit_log: str = Field("audit_log", env="SUPABASE_TABLE_AUDIT_LOG")
    supabase_table_iso_controls: str = Field("iso_controls", env="SUPABASE_TABLE_ISO_CONTROLS")

    # OpenAI
    openai_api_key: str = Field(..., env="OPENAI_API_KEY")
    openai_model: str = Field("gpt-3.5-turbo", env="OPENAI_MODEL")
    embedding_model: str = Field("text-embedding-ada-002", env="EMBEDDING_MODEL")

    # Authentication
    jwt_secret_key: str = Field(..., env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field("HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    
    # User Roles
    valid_user_roles: List[str] = Field(
        default=["admin", "compliance_officer", "reader"], 
        env="VALID_USER_ROLES"
    )
    default_user_role: str = Field("reader", env="DEFAULT_USER_ROLE")
    admin_role: str = Field("admin", env="ADMIN_ROLE")
    compliance_officer_role: str = Field("compliance_officer", env="COMPLIANCE_OFFICER_ROLE")
    reader_role: str = Field("reader", env="READER_ROLE")
    
    # RAG params
    top_k: int = Field(5, env="TOP_K")
    pdf_dir: str = Field("pdfs/", env="PDF_DIR")
    reports_dir: str = Field("reports/", env="REPORTS_DIR")

    class Config:
        env_file = ".env"
    
    def is_valid_role(self, role: str) -> bool:
        return role in self.valid_user_roles
    
    def is_admin_role(self, role: str) -> bool:
        return role == self.admin_role
    
    def is_compliance_officer_role(self, role: str) -> bool:
        return role == self.compliance_officer_role
    
    def is_reader_role(self, role: str) -> bool:
        return role == self.reader_role
    
    def has_elevated_permissions(self, role: str) -> bool:
        return role in [self.admin_role, self.compliance_officer_role]

settings = Settings()

tags_metadata = [
    {
        "name": "Authentication",
        "description": "User authentication and authorization endpoints.",
    },
    {
        "name": "Health",
        "description": "Health-check and diagnostics endpoints.",
    },
    {
        "name": "Documents",
        "description": "List and retrieve stored documents.",
    },
    {
        "name": "RAG",
        "description": "Retrieval-Augmented Generation (Q&A) endpoints.",
    },
    {
        "name": "History",
        "description": "Chat history operations.",
    },
    {
        "name": "Ingestion",
        "description": "PDF ingestion and embedding endpoints.",        
    },
    {
        "name": "Audit",
        "description": "Document access logging and audit trail operations.",
    },
    {
        "name": "Audit Sessions",
        "description": "Audit session management and tracking operations.",
    },
    {
        "name": "Compliance",
        "description": "Compliance domain management operations.",
    },
    {
        "name": "Compliance Gaps",
        "description": "Compliance gaps operations.",
    },
    {
        "name": "Users",
        "description": "User-related operations and history.",
    },
    {
        "name": "Audit",
        "description": "Audit trail and access logging.",
    },
    {
        "name": "ISO Controls",
        "description": "ISO Control Management.",
    },
]