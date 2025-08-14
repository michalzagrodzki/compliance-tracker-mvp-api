from decimal import Decimal, InvalidOperation
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid
from fastapi import HTTPException
from db.supabase_client import create_supabase_client
from config.config import settings

logger = logging.getLogger(__name__)
supabase = create_supabase_client()

def list_compliance_gaps(
    skip: int = 0, 
    limit: int = 10,
    compliance_domain: Optional[str] = None,
    gap_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    status: Optional[str] = None,
    assigned_to: Optional[str] = None,
    user_id: Optional[str] = None,
    audit_session_id: Optional[str] = None,
    detection_method: Optional[str] = None,
    regulatory_requirement: Optional[bool] = None
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching compliance gaps: skip={skip}, limit={limit}")
        
        query = (
            supabase
            .table(settings.supabase_table_compliance_gaps)
            .select("""
                id, user_id, chat_history_id, audit_session_id, compliance_domain,
                pdf_ingestion_id, gap_type, gap_category, gap_title, gap_description,
                original_question, expected_answer_type, search_terms_used,
                similarity_threshold_used, best_match_score, risk_level, business_impact,
                regulatory_requirement, potential_fine_amount, status, assigned_to,
                due_date, resolution_notes, recommendation_type, recommendation_text,
                recommended_actions, related_documents, detection_method,
                confidence_score, auto_generated, false_positive_likelihood,
                detected_at, acknowledged_at, resolved_at, last_reviewed_at,
                created_at, updated_at, ip_address, user_agent, session_context
            """)
            .order("detected_at", desc=True)
            .limit(limit)
            .offset(skip)
        )

        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
        if gap_type:
            query = query.eq("gap_type", gap_type)
        if risk_level:
            query = query.eq("risk_level", risk_level)
        if status:
            query = query.eq("status", status)
        if assigned_to:
            query = query.eq("assigned_to", assigned_to)
        if user_id:
            query = query.eq("user_id", user_id)
        if audit_session_id:
            query = query.eq("audit_session_id", audit_session_id)
        if detection_method:
            query = query.eq("detection_method", detection_method)
        if regulatory_requirement is not None:
            query = query.eq("regulatory_requirement", regulatory_requirement)
            
        resp = query.execute()
        
        logger.info(f"Received {len(resp.data)} compliance gaps")
        return resp.data
        
    except Exception as e:
        logger.error("Failed to fetch compliance gaps", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def list_compliance_gaps_by_compliance_domains(
    compliance_domains: List[str], 
    skip: int = 0, 
    limit: int = 50,
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching gaps for domains: {compliance_domains}")
        
        query = (
            supabase
            .table(settings.supabase_table_compliance_gaps)
            .select("*")
            .in_("compliance_domain", compliance_domains)
            .order("risk_level", desc=True)
            .order("detected_at", desc=True)
            .limit(limit)
            .offset(skip)
        )
        
        resp = query.execute()
        
        logger.info(f"Found {len(resp.data)} gaps for domains {compliance_domains}")
        return resp.data
        
    except Exception as e:
        logger.error(f"Failed to fetch gaps for domains {compliance_domains}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    
def get_compliance_gap_by_id(gap_id: str) -> Dict[str, Any]:
    try:
        logger.info(f"Fetching compliance gap with ID: {gap_id}")
        resp = (
            supabase
            .table(settings.supabase_table_compliance_gaps)
            .select("*")
            .eq("id", gap_id)
            .execute()
        )
        
        if not resp.data:
            raise HTTPException(status_code=404, detail=f"Compliance gap with ID '{gap_id}' not found")
        
        logger.info(f"Found compliance gap: {gap_id}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch compliance gap {gap_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def create_compliance_gap(gap_data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        logger.info(f"Creating compliance gap for domain: {gap_data.get('compliance_domain')}")

        # Ensure required timestamps are present and properly formatted as ISO strings
        if "detected_at" not in gap_data:
            gap_data["detected_at"] = datetime.now(timezone.utc).isoformat()
        elif isinstance(gap_data["detected_at"], datetime):
            gap_data["detected_at"] = gap_data["detected_at"].isoformat()
            
        if "created_at" not in gap_data:
            gap_data["created_at"] = datetime.now(timezone.utc).isoformat()
        elif isinstance(gap_data["created_at"], datetime):
            gap_data["created_at"] = gap_data["created_at"].isoformat()
            
        if "updated_at" not in gap_data:
            gap_data["updated_at"] = datetime.now(timezone.utc).isoformat()
        elif isinstance(gap_data["updated_at"], datetime):
            gap_data["updated_at"] = gap_data["updated_at"].isoformat()

        # Convert any other datetime fields to ISO strings
        datetime_fields = [
            "acknowledged_at", "resolved_at", "last_reviewed_at", "due_date"
        ]
        for field in datetime_fields:
            if field in gap_data and isinstance(gap_data[field], datetime):
                gap_data[field] = gap_data[field].isoformat()

        # Set default values if not provided
        gap_data.setdefault("status", "identified")
        gap_data.setdefault("risk_level", "medium")
        gap_data.setdefault("business_impact", "medium")
        gap_data.setdefault("auto_generated", False)
        gap_data.setdefault("confidence_score", 0.80)
        gap_data.setdefault("false_positive_likelihood", 0.20)
        gap_data.setdefault("detection_method", "manual_review")
        gap_data.setdefault("regulatory_requirement", False)
        gap_data.setdefault("recommended_actions", [])
        gap_data.setdefault("session_context", {})
        
        # Handle UUID fields - ensure they are properly formatted strings
        uuid_fields = ["user_id", "audit_session_id", "assigned_to", "pdf_ingestion_id"]
        for field in uuid_fields:
            if field in gap_data and gap_data[field] and not isinstance(gap_data[field], str):
                gap_data[field] = str(gap_data[field])
        
        # Handle chat_history_id specifically - it's a BIGINT, not UUID
        if "chat_history_id" in gap_data and gap_data["chat_history_id"]:
            try:
                # Convert to integer if it's a string number
                gap_data["chat_history_id"] = int(gap_data["chat_history_id"])
            except (ValueError, TypeError):
                logger.warning(f"Invalid chat_history_id format: {gap_data['chat_history_id']}")
                gap_data["chat_history_id"] = None
        
        # Handle potential_fine_amount - ensure it's a proper decimal/float
        if "potential_fine_amount" in gap_data and gap_data["potential_fine_amount"]:
            try:
                gap_data["potential_fine_amount"] = float(gap_data["potential_fine_amount"])
            except (ValueError, TypeError):
                logger.warning(f"Invalid potential_fine_amount: {gap_data['potential_fine_amount']}")
                gap_data["potential_fine_amount"] = None
        
        # Handle confidence_score and false_positive_likelihood - ensure they're floats
        decimal_fields = ["confidence_score", "false_positive_likelihood", "similarity_threshold_used", "best_match_score"]
        for field in decimal_fields:
            if field in gap_data and gap_data[field] is not None:
                try:
                    gap_data[field] = float(gap_data[field])
                except (ValueError, TypeError):
                    logger.warning(f"Invalid {field}: {gap_data[field]}")
                    gap_data[field] = None
        
        # Convert Decimal objects to floats for Supabase compatibility
        for key, value in gap_data.items():
            if isinstance(value, Decimal):
                gap_data[key] = float(value)
        
        # Ensure array fields are properly formatted
        array_fields = ["search_terms_used", "related_documents", "recommended_actions"]
        for field in array_fields:
            if field in gap_data and gap_data[field] is not None:
                if not isinstance(gap_data[field], list):
                    # If it's a single value, wrap it in a list
                    gap_data[field] = [gap_data[field]] if gap_data[field] else []
        
        # Validate required fields according to schema
        required_fields = [
            "user_id", "audit_session_id", "compliance_domain", "gap_type", 
            "gap_category", "gap_title", "gap_description", "original_question"
        ]
        
        missing_fields = [field for field in required_fields if field not in gap_data or gap_data[field] is None]
        if missing_fields:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required fields: {', '.join(missing_fields)}"
            )
        
        # Validate enum values
        valid_gap_types = ['missing_policy', 'outdated_policy', 'low_confidence', 'conflicting_policies', 'incomplete_coverage', 'no_evidence']
        if gap_data["gap_type"] not in valid_gap_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid gap_type. Must be one of: {', '.join(valid_gap_types)}"
            )
        
        valid_risk_levels = ['low', 'medium', 'high', 'critical']
        if gap_data["risk_level"] not in valid_risk_levels:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid risk_level. Must be one of: {', '.join(valid_risk_levels)}"
            )
        
        valid_business_impacts = ['low', 'medium', 'high', 'critical']
        if gap_data["business_impact"] not in valid_business_impacts:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid business_impact. Must be one of: {', '.join(valid_business_impacts)}"
            )

        nullable_fields = {
            "chat_history_id", "pdf_ingestion_id", "expected_answer_type", 
            "similarity_threshold_used", "best_match_score", "potential_fine_amount",
            "assigned_to", "due_date", "resolution_notes", "recommendation_type",
            "recommendation_text", "acknowledged_at", "resolved_at", "last_reviewed_at",
            "ip_address", "user_agent", "assigned_to", "due_date" "resolution_notes"
        }
        
        filtered_gap_data = {}
        for key, value in gap_data.items():
            if value is not None or key in nullable_fields:
                filtered_gap_data[key] = value
        
        resp = (
            supabase
            .table(settings.supabase_table_compliance_gaps)
            .insert(filtered_gap_data)
            .execute()
        )
        
        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase compliance gap creation failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to create compliance gap: {resp.error.message}"
            )
        
        if not resp.data:
            raise HTTPException(
                status_code=500,
                detail="Failed to create compliance gap: No data returned from database"
            )
        
        logger.info(f"Created compliance gap with ID: {resp.data[0]['id']}")
        return resp.data[0]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create compliance gap", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def update_compliance_gap(gap_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        logger.info(f"Updating compliance gap {gap_id}")
        try:
            uuid.UUID(gap_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid gap_id format (must be UUID)")
        processed_data = update_data.copy()

        if "updated_at" not in processed_data:
            processed_data["updated_at"] = datetime.now(timezone.utc).isoformat()
        elif isinstance(processed_data["updated_at"], datetime):
            processed_data["updated_at"] = processed_data["updated_at"].isoformat()

        if "status" in processed_data:
            status = processed_data["status"]
            if status == "acknowledged" and "acknowledged_at" not in processed_data:
                processed_data["acknowledged_at"] = datetime.now(timezone.utc).isoformat()
            elif status == "resolved" and "resolved_at" not in processed_data:
                processed_data["resolved_at"] = datetime.now(timezone.utc).isoformat()

        datetime_fields = ["due_date", "acknowledged_at", "resolved_at", "last_reviewed_at"]
        for field in datetime_fields:
            if field in processed_data and isinstance(processed_data[field], datetime):
                processed_data[field] = processed_data[field].isoformat()

        uuid_fields = ["assigned_to", "pdf_ingestion_id"]
        for field in uuid_fields:
            if field in processed_data and processed_data[field] is not None:
                if not isinstance(processed_data[field], str):
                    processed_data[field] = str(processed_data[field])

        decimal_fields = [
            "potential_fine_amount", "confidence_score", 
            "false_positive_likelihood", "similarity_threshold_used", "best_match_score"
        ]
        for field in decimal_fields:
            if field in processed_data and processed_data[field] is not None:
                try:
                    if isinstance(processed_data[field], Decimal):
                        processed_data[field] = float(processed_data[field])
                    elif isinstance(processed_data[field], (int, str)):
                        processed_data[field] = float(processed_data[field])
                except (ValueError, TypeError, InvalidOperation):
                    logger.warning(f"Invalid {field} value: {processed_data[field]}")
                    processed_data.pop(field, None)

        array_fields = ["search_terms_used", "related_documents", "recommended_actions"]
        for field in array_fields:
            if field in processed_data:
                if processed_data[field] is not None:
                    if not isinstance(processed_data[field], list):
                        processed_data[field] = [processed_data[field]] if processed_data[field] else []
                    if field in ["search_terms_used", "related_documents"]:
                        processed_data[field] = [str(item) for item in processed_data[field]]

        json_fields = ["session_context"]
        for field in json_fields:
            if field in processed_data:
                if processed_data[field] is not None and not isinstance(processed_data[field], dict):
                    logger.warning(f"Invalid {field} format, expected dict")
                    processed_data.pop(field, None)

        if "gap_type" in processed_data:
            valid_gap_types = [
                'missing_policy', 'outdated_policy', 'low_confidence', 
                'conflicting_policies', 'incomplete_coverage', 'no_evidence'
            ]
            if processed_data["gap_type"] not in valid_gap_types:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid gap_type. Must be one of: {', '.join(valid_gap_types)}"
                )

        if "risk_level" in processed_data:
            valid_risk_levels = ['low', 'medium', 'high', 'critical']
            if processed_data["risk_level"] not in valid_risk_levels:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid risk_level. Must be one of: {', '.join(valid_risk_levels)}"
                )

        if "business_impact" in processed_data:
            valid_business_impacts = ['low', 'medium', 'high', 'critical']
            if processed_data["business_impact"] not in valid_business_impacts:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid business_impact. Must be one of: {', '.join(valid_business_impacts)}"
                )

        if "status" in processed_data:
            valid_statuses = [
                'identified', 'acknowledged', 'in_progress', 'resolved', 
                'false_positive', 'accepted_risk'
            ]
            if processed_data["status"] not in valid_statuses:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
                )

        if "confidence_score" in processed_data and processed_data["confidence_score"] is not None:
            score = processed_data["confidence_score"]
            if not (0 <= score <= 1):
                raise HTTPException(
                    status_code=400,
                    detail="confidence_score must be between 0 and 1"
                )

        if "false_positive_likelihood" in processed_data and processed_data["false_positive_likelihood"] is not None:
            likelihood = processed_data["false_positive_likelihood"]
            if not (0 <= likelihood <= 1):
                raise HTTPException(
                    status_code=400,
                    detail="false_positive_likelihood must be between 0 and 1"
                )

        filtered_data = {}
        for key, value in processed_data.items():
            if value is not None and value != "":
                filtered_data[key] = value

        if not filtered_data:
            raise HTTPException(
                status_code=400, 
                detail="No valid update data provided after processing"
            )

        resp = (
            supabase
            .table(settings.supabase_table_compliance_gaps)
            .update(filtered_data)
            .eq("id", gap_id)
            .execute()
        )

        if hasattr(resp, "error") and resp.error:
            logger.error("Supabase compliance gap update failed", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to update compliance gap: {resp.error.message}"
            )

        if not resp.data:
            raise HTTPException(
                status_code=404, 
                detail=f"Compliance gap {gap_id} not found"
            )

        logger.info(f"Successfully updated compliance gap {gap_id}")
        return resp.data[0]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update compliance gap {gap_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

def update_gap_status(gap_id: str, new_status: str, resolution_notes: Optional[str] = None) -> Dict[str, Any]:
    try:
        logger.info(f"Updating status of compliance gap {gap_id} to {new_status}")
        
        valid_statuses = ['identified', 'acknowledged', 'in_progress', 'resolved', 'false_positive', 'accepted_risk']
        if new_status not in valid_statuses:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
            )
        
        update_data = {
            "status": new_status,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        if new_status == "acknowledged":
            update_data["acknowledged_at"] = datetime.now(timezone.utc).isoformat()
        elif new_status == "resolved":
            update_data["resolved_at"] = datetime.now(timezone.utc).isoformat()
        
        if resolution_notes:
            update_data["resolution_notes"] = resolution_notes
        
        return update_compliance_gap(gap_id, update_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update gap status {gap_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def assign_gap_to_user(gap_id: str, assigned_to: str, due_date: Optional[datetime] = None) -> Dict[str, Any]:
    try:
        logger.info(f"Assigning compliance gap {gap_id} to user {assigned_to}")
        
        update_data = {
            "assigned_to": assigned_to,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        if due_date:
            update_data["due_date"] = due_date.isoformat()
        
        return update_compliance_gap(gap_id, update_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to assign gap {gap_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def mark_gap_reviewed(gap_id: str, reviewer_notes: Optional[str] = None) -> Dict[str, Any]:
    try:
        logger.info(f"Marking compliance gap {gap_id} as reviewed")
        
        update_data = {
            "last_reviewed_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat()
        }
        
        if reviewer_notes:
            existing_gap = get_compliance_gap_by_id(gap_id)
            existing_notes = existing_gap.get("resolution_notes", "")
            review_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            new_note = f"[Review {review_timestamp}] {reviewer_notes}"
            
            if existing_notes:
                update_data["resolution_notes"] = f"{existing_notes}\n\n{new_note}"
            else:
                update_data["resolution_notes"] = new_note
        
        return update_compliance_gap(gap_id, update_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to mark gap reviewed {gap_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_gaps_by_domain(
    compliance_domain: str, 
    skip: int = 0, 
    limit: int = 50,
    status_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching gaps for domain: {compliance_domain}")
        
        query = (
            supabase
            .table(settings.supabase_table_compliance_gaps)
            .select("*")
            .eq("compliance_domain", compliance_domain)
            .order("risk_level", desc=True)  # Show highest risk first
            .order("detected_at", desc=True)
            .limit(limit)
            .offset(skip)
        )
        
        if status_filter:
            query = query.eq("status", status_filter)
        
        resp = query.execute()
        
        logger.info(f"Found {len(resp.data)} gaps for domain {compliance_domain}")
        return resp.data
        
    except Exception as e:
        logger.error(f"Failed to fetch gaps for domain {compliance_domain}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_gaps_by_user(
    user_id: str, 
    skip: int = 0, 
    limit: int = 50,
    assigned_only: bool = False
) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching gaps for user: {user_id}")
        
        if assigned_only:
            query = (
                supabase
                .table(settings.supabase_table_compliance_gaps)
                .select("*")
                .eq("assigned_to", user_id)
            )
        else:
            query = (
                supabase
                .table(settings.supabase_table_compliance_gaps)
                .select("*")
                .eq("user_id", user_id)
            )
        
        resp = (
            query
            .order("detected_at", desc=True)
            .limit(limit)
            .offset(skip)
            .execute()
        )
        
        logger.info(f"Found {len(resp.data)} gaps for user {user_id}")
        return resp.data
        
    except Exception as e:
        logger.error(f"Failed to fetch gaps for user {user_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_gaps_by_audit_session(audit_session_id: str) -> List[Dict[str, Any]]:
    try:
        logger.info(f"Fetching gaps for audit session: {audit_session_id}")
        
        resp = (
            supabase
            .table(settings.supabase_table_compliance_gaps)
            .select("*")
            .eq("audit_session_id", audit_session_id)
            .order("risk_level", desc=True)
            .order("detected_at", desc=False)
            .execute()
        )
        
        logger.info(f"Found {len(resp.data)} gaps for audit session {audit_session_id}")
        return resp.data
        
    except Exception as e:
        logger.error(f"Failed to fetch gaps for audit session {audit_session_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_compliance_gaps_statistics(
    compliance_domain: Optional[str] = None,
    user_id: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
) -> Dict[str, Any]:
    try:
        logger.info("Generating compliance gaps statistics")

        query = supabase.table(settings.supabase_table_compliance_gaps).select("*")
        
        if compliance_domain:
            query = query.eq("compliance_domain", compliance_domain)
        if user_id:
            query = query.eq("user_id", user_id)
        if start_date:
            query = query.gte("detected_at", start_date.isoformat())
        if end_date:
            query = query.lte("detected_at", end_date.isoformat())
        
        resp = query.execute()
        gaps = resp.data

        total_gaps = len(gaps)

        status_counts = {}
        risk_counts = {}
        domain_counts = {}
        gap_type_counts = {}
        
        regulatory_gaps = 0
        total_potential_fines = 0
        avg_confidence = 0
        
        for gap in gaps:
            status = gap.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1

            risk = gap.get("risk_level", "unknown")
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

            domain = gap.get("compliance_domain", "unknown")
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

            gap_type = gap.get("gap_type", "unknown")
            gap_type_counts[gap_type] = gap_type_counts.get(gap_type, 0) + 1

            if gap.get("regulatory_requirement"):
                regulatory_gaps += 1
            
            fine_amount = gap.get("potential_fine_amount")
            if fine_amount:
                total_potential_fines += float(fine_amount)
            
            confidence = gap.get("confidence_score")
            if confidence:
                avg_confidence += float(confidence)
        
        avg_confidence = avg_confidence / total_gaps if total_gaps > 0 else 0

        resolved_gaps = status_counts.get("resolved", 0) + status_counts.get("false_positive", 0)
        resolution_rate = (resolved_gaps / total_gaps * 100) if total_gaps > 0 else 0
        
        stats = {
            "total_gaps": total_gaps,
            "regulatory_gaps": regulatory_gaps,
            "total_potential_fines": round(total_potential_fines, 2),
            "avg_confidence_score": round(avg_confidence, 2),
            "resolution_rate_percent": round(resolution_rate, 2),
            "status_breakdown": status_counts,
            "risk_level_breakdown": risk_counts,
            "domain_breakdown": domain_counts,
            "gap_type_breakdown": gap_type_counts,
            "filters_applied": {
                "compliance_domain": compliance_domain,
                "user_id": user_id,
                "start_date": start_date.isoformat() if start_date else None,
                "end_date": end_date.isoformat() if end_date else None
            }
        }
        
        logger.info(f"Generated statistics for {total_gaps} compliance gaps")
        return stats
        
    except Exception as e:
        logger.error("Failed to generate compliance gaps statistics", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

def get_document_by_id(document_id: str) -> Optional[Dict[str, Any]]:
    try:
        logger.info(f"Fetching document with ID: {document_id}")
        resp = (
            supabase
            .table(settings.supabase_table_documents)
            .select("id, content, metadata, compliance_domain, document_version, source_filename, source_page_number")
            .eq("id", document_id)
            .execute()
        )
        
        if not resp.data:
            logger.warning(f"Document with ID {document_id} not found")
            return None
        
        logger.info(f"Found document: {document_id}")
        return resp.data[0]
        
    except Exception as e:
        logger.error(f"Failed to fetch document with ID {document_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
  
def get_chat_history_by_id(chat_history_id: str) -> Optional[Dict[str, Any]]:
    try:
        logger.info(f"Fetching chat history with ID: {chat_history_id}")
        resp = (
            supabase
            .table(settings.supabase_table_chat_history)
            .select("""
                id, conversation_id, question, answer, created_at,
                audit_session_id, compliance_domain, source_document_ids,
                match_threshold, match_count, user_id, response_time_ms, total_tokens_used
            """)
            .eq("id", chat_history_id)
            .execute()
        )
        
        if not resp.data:
            logger.warning(f"Chat history with ID {chat_history_id} not found")
            return None
        
        # Process the row to ensure all IDs are strings
        row = resp.data[0]
        processed_row = {
            "id": str(row["id"]),
            "conversation_id": str(row["conversation_id"]),
            "question": row["question"],
            "answer": row["answer"],
            "created_at": row["created_at"],
            "audit_session_id": str(row["audit_session_id"]) if row["audit_session_id"] else None,
            "compliance_domain": row["compliance_domain"],
            "source_document_ids": [str(doc_id) for doc_id in (row["source_document_ids"] or [])],
            "match_threshold": float(row["match_threshold"]) if row["match_threshold"] else None,
            "match_count": row["match_count"],
            "user_id": str(row["user_id"]) if row["user_id"] else None,
            "response_time_ms": row["response_time_ms"],
            "total_tokens_used": row["total_tokens_used"]
        }
        
        logger.info(f"Found chat history: {chat_history_id}")
        return processed_row
        
    except Exception as e:
        logger.error(f"Failed to fetch chat history with ID {chat_history_id}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Database error: {e}")