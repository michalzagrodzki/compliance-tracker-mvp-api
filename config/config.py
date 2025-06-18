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

    # OpenAI
    openai_api_key: str = Field(..., env="OPENAI_API_KEY")
    openai_model: str = Field("gpt-3.5-turbo", env="OPENAI_MODEL")
    embedding_model: str = Field("text-embedding-ada-002", env="EMBEDDING_MODEL")

    # RAG params
    top_k: int = Field(5, env="TOP_K")
    pdf_dir: str = Field("pdfs/", env="PDF_DIR")
    class Config:
        env_file = ".env"

settings = Settings()

tags_metadata = [
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
        "name": "Users",
        "description": "User-related operations and history.",
    },
]