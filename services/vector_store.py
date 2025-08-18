from langchain_community.vectorstores import SupabaseVectorStore
from langchain.schema import Document
from config.config import settings
from db.supabase_client import create_supabase_client
from typing import List, Optional, Dict, Any
import logging
import uuid

logger = logging.getLogger(__name__)

class ComplianceSupabaseVectorStore(SupabaseVectorStore):
    def __init__(self, *args, embedding_adapter=None, **kwargs):
        super().__init__(*args, **kwargs)
        # Optional adapter to decouple embeddings provider
        self._embedding_adapter = embedding_adapter

    def add_documents(self, documents: List[Document], **kwargs) -> List[str]:
        texts = [doc.page_content for doc in documents]
        metadatas = [doc.metadata for doc in documents]
        return self.add_texts(texts, metadatas, **kwargs)
    
    def add_texts(
        self,
        texts: List[str],
        metadatas: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> List[str]:
        if not metadatas:
            metadatas = [{}] * len(texts)

        # Use adapter if provided; fallback to LangChain embedding instance
        if getattr(self, "_embedding_adapter", None) is not None:
            embeddings = self._embedding_adapter.embed_texts(texts, model=getattr(settings, "embedding_model", None))
        else:
            embeddings = self._embedding.embed_documents(texts)
        
        records = []
        for i, (text, metadata, embedding) in enumerate(zip(texts, metadatas, embeddings)):
            compliance_data = self._extract_compliance_data(metadata, i)
            
            record = {
                "content": text,
                "embedding": embedding,
                "metadata": metadata,
                "compliance_domain": compliance_data.get("compliance_domain"),
                "document_version": compliance_data.get("document_version"),
                "document_tags": compliance_data.get("document_tags"),
                "uploaded_by": compliance_data.get("uploaded_by"),
                "approved_by": compliance_data.get("approved_by"),
                "approval_status": compliance_data.get("approval_status", "pending"),
                "source_filename": compliance_data.get("source_filename"),
                "source_page_number": compliance_data.get("source_page_number"),
                "chunk_index": compliance_data.get("chunk_index", i)
            }
            
            records.append(record)
        
        try:
            resp = self._client.table(self.table_name).insert(records).execute()
            
            if hasattr(resp, "error") and resp.error:
                logger.error("Failed to insert documents into vector store", exc_info=True)
                raise Exception(f"Vector store insertion failed: {resp.error.message}")

            inserted_ids = [str(record["id"]) for record in resp.data]
            logger.info(f"Successfully inserted {len(inserted_ids)} documents into vector store")
            
            return inserted_ids
            
        except Exception as e:
            logger.error(f"Error inserting documents into vector store: {e}", exc_info=True)
            raise
    
    def _extract_compliance_data(self, metadata: Dict[str, Any], chunk_index: int) -> Dict[str, Any]:
        page_number = None
        if "page" in metadata:
            page_number = metadata["page"]
        elif "source" in metadata and "page" in str(metadata["source"]):
            try:
                source_str = str(metadata["source"])
                if "page" in source_str.lower():
                    import re
                    page_match = re.search(r'page[_\s]*(\d+)', source_str.lower())
                    if page_match:
                        page_number = int(page_match.group(1))
            except:
                pass

        def safe_uuid_convert(value):
            if value is None:
                return None
            if isinstance(value, uuid.UUID):
                return value
            if isinstance(value, str):
                try:
                    return uuid.UUID(value)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid UUID format: {value}")
                    return None
            return None

        return {
            "compliance_domain": metadata.get("compliance_domain"),
            "document_version": metadata.get("document_version"),
            "document_tags": metadata.get("document_tags", []),
            "uploaded_by": metadata.get("uploaded_by"),
            "approved_by": metadata.get("approved_by"),
            "approval_status": metadata.get("approval_status", "approved"),
            "source_filename": metadata.get("filename") or metadata.get("source_filename"),
            "source_page_number": page_number,
            "chunk_index": chunk_index,
            "document_title": metadata.get("title"),
            "document_author": metadata.get("author") 
        }

supabase = create_supabase_client()

# Prefer our adapter if available; fall back to LangChain embeddings.
try:
    from adapters.embeddings_adapter import OpenAIEmbeddingsAdapter, MockEmbeddingsAdapter
    embedding_adapter = None
    api_key = getattr(settings, "openai_api_key", None)
    if api_key:
        embedding_adapter = OpenAIEmbeddingsAdapter(api_key=api_key, default_model=settings.embedding_model)
    else:
        embedding_adapter = MockEmbeddingsAdapter()
    vector_store = ComplianceSupabaseVectorStore(
        client=supabase,
        embedding=None,  # not used when adapter present
        table_name=settings.supabase_table_documents,
        embedding_adapter=embedding_adapter,
    )
except Exception:
    # Fallback: use LangChain OpenAIEmbeddings directly
    try:
        from langchain_openai import OpenAIEmbeddings
        embeddings = OpenAIEmbeddings(
            model=settings.embedding_model,
            openai_api_key=settings.openai_api_key,
        )
        vector_store = ComplianceSupabaseVectorStore(
            client=supabase,
            embedding=embeddings,
            table_name=settings.supabase_table_documents,
        )
    except Exception as e:
        logger.error(f"Failed to initialize embeddings: {e}")
        raise
