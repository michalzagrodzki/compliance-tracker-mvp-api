from supabase import create_client, Client
from config.config import settings

def create_supabase_client() -> Client:
    """
    Create and return a Supabase client using settings from config.
    """
    return create_client(settings.supabase_url, settings.supabase_key)