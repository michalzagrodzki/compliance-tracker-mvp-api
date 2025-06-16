from langchain_community.vectorstores import SupabaseVectorStore
from langchain_openai import OpenAIEmbeddings
from config.config import settings
from db.supabase_client import create_supabase_client

supabase = create_supabase_client()

embeddings = OpenAIEmbeddings(
    model=settings.embedding_model,
    openai_api_key=settings.openai_api_key,
)

vector_store = SupabaseVectorStore(
    client=supabase,
    embedding=embeddings,
    table_name=settings.supabase_table_documents,
)