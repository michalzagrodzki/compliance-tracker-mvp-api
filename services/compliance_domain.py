"""
Compliance Domain service using simple Supabase access.

Converted to a class so it can be injected via DI.
"""

from typing import List, Dict, Any, Optional
from fastapi import HTTPException

from common.logging import get_logger
from config.config import settings

logger = get_logger("compliance_domain_service")


class ComplianceDomainService:
    """
    Service for querying compliance domains.
    Uses the provided Supabase client; no repository abstraction yet.
    """

    def __init__(self, supabase_client: Any):
        self.supabase = supabase_client
        self.table_name = settings.supabase_table_compliance_domains

    def list_compliance_domains(
        self,
        skip: int = 0,
        limit: int = 10,
        is_active: Optional[bool] = True,
    ) -> List[Dict[str, Any]]:
        """Fetch paginated compliance domains from Supabase."""
        try:
            logger.info(
                f"Fetching compliance domains: skip={skip}, limit={limit}, is_active={is_active}"
            )

            query = (
                self.supabase
                .table(self.table_name)
                .select("code, name, description, is_active, created_at")
                .limit(limit)
                .offset(skip)
                .order("name")
            )

            if is_active is not None:
                query = query.eq("is_active", is_active)

            resp = query.execute()
            logger.info(f"Received {len(resp.data)} compliance domains")
            return resp.data
        except Exception as e:
            logger.error("Failed to fetch compliance domains", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Database error: {e}")

    def get_compliance_domain_by_code(self, code: str) -> Dict[str, Any]:
        """Fetch a single compliance domain by code."""
        try:
            logger.info(f"Fetching compliance domain with code: {code}")
            resp = (
                self.supabase
                .table(self.table_name)
                .select("code, name, description, is_active, created_at")
                .eq("code", code)
                .execute()
            )

            if not resp.data:
                raise HTTPException(
                    status_code=404,
                    detail=f"Compliance domain with code '{code}' not found",
                )

            logger.info(f"Found compliance domain: {code}")
            return resp.data[0]
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Failed to fetch compliance domain {code}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Database error: {e}")


# Factory function (for DI setup)
def create_compliance_domain_service(supabase_client: Any) -> ComplianceDomainService:
    """Factory to create a ComplianceDomainService instance."""
    return ComplianceDomainService(supabase_client)
