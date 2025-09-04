"""
Audit Report service using Repository pattern.
"""

import json
from typing import List, Dict, Any

from repositories.audit_report_repository import AuditReportRepository
from repositories.user_repository import UserRepository
from repositories.chat_history_repository import ChatHistoryRepository
from repositories.compliance_gap_repository import ComplianceGapRepository
from repositories.audit_session_repository import AuditSessionRepository
from common.exceptions import (
    ResourceNotFoundException,
    ValidationException,
    BusinessLogicException,
)
from common.logging import get_logger, log_business_event, log_performance

logger = get_logger("audit_report_service")

class AuditReportService:
    """
    Audit Report service using Repository pattern.
    Handles business logic for audit report listing and CRUD operations.
    """

    def __init__(
        self,
        report_repository: AuditReportRepository,
        user_repository: UserRepository,
        chat_history_repository: ChatHistoryRepository,
        compliance_gap_repository: ComplianceGapRepository,
        audit_session_repository: AuditSessionRepository,
    ):
        self.report_repository = report_repository
        self.user_repository = user_repository
        self.chat_history_repository = chat_history_repository
        self.compliance_gap_repository = compliance_gap_repository
        self.audit_session_repository = audit_session_repository

    async def list_reports_by_domains(self, user_id: str, domains: List[str]) -> List[Dict[str, Any]]:
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(detail="Invalid or inactive user", field="user_id", value=user_id)
            reports = await self.report_repository.get_by_domains(domains)
            return [self._deserialize_report_fields(report) for report in reports]
        except ValidationException:
            raise
        except Exception:
            logger.error("Failed to list audit reports by domains", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit reports by domains",
                error_code="AUDIT_REPORT_LIST_BY_DOMAINS_FAILED",
            )

    async def get_report_by_id(self, report_id: str, user_id: str) -> Dict[str, Any]:
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise ValidationException(detail="Invalid user", field="user_id", value=user_id)

            report = await self.report_repository.get_by_id(report_id)
            if not report:
                raise ResourceNotFoundException(resource_type="AuditReport", resource_id=report_id)
            
            # Deserialize JSON strings back to Python objects for client consumption
            report = self._deserialize_report_fields(report)
            return report
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception:
            logger.error(f"Failed to get audit report {report_id}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to retrieve audit report",
                error_code="AUDIT_REPORT_RETRIEVAL_FAILED",
                context={"report_id": report_id},
            )

    async def create_report(self, report_data: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        try:
            import time
            start = time.time()
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(detail="Invalid or inactive user", field="user_id", value=user_id)

            # Non-admin users cannot create reports for other users
            if not user.is_admin() and str(report_data.get("user_id")) != str(user_id):
                report_data["user_id"] = user_id

            # Normalize recommendations/action_items to JSON strings to avoid downstream warnings
            def _as_json_array(val: Any) -> str:
                import json as _json
                if val is None:
                    return "[]"
                if isinstance(val, (list, tuple)):
                    return _json.dumps(list(val))
                if isinstance(val, str):
                    s = val.strip()
                    if not s:
                        return "[]"
                    try:
                        parsed = _json.loads(s)
                        if isinstance(parsed, (list, dict)):
                            return _json.dumps(parsed)
                    except Exception:
                        # Fall through to wrap string as a single item array
                        return _json.dumps([s])
                # Fallback: wrap as array
                try:
                    return _json.dumps([val])
                except Exception:
                    return "[]"

            if "recommendations" in report_data:
                report_data["recommendations"] = _as_json_array(report_data.get("recommendations"))
            if "action_items" in report_data:
                report_data["action_items"] = _as_json_array(report_data.get("action_items"))

            created = await self.report_repository.create(report_data)
            
            # Deserialize for return
            created = self._deserialize_report_fields(created)

            # Business event logging
            log_business_event(
                event_type="AUDIT_REPORT_CREATED",
                entity_type="audit_report",
                entity_id=created.get("id"),
                action="create",
                user_id=user_id,
                details={"title": created.get("report_title"), "domain": created.get("compliance_domain")},
            )
            log_performance(
                operation="create_audit_report",
                duration_ms=(time.time() - start) * 1000,
                success=True,
                item_count=1,
            )
            return created
        except ValidationException:
            raise
        except Exception:
            logger.error("Failed to create audit report", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to create audit report",
                error_code="AUDIT_REPORT_CREATION_FAILED",
            )

    async def update_report(self, report_id: str, update_data: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        try:
            user = await self.user_repository.get_by_id(user_id)
            if not user or not user.is_active:
                raise ValidationException(detail="Invalid or inactive user", field="user_id", value=user_id)

            updated = await self.report_repository.update(report_id, update_data)
            if not updated:
                raise ResourceNotFoundException(resource_type="AuditReport", resource_id=report_id)
            return self._deserialize_report_fields(updated)
        except (ResourceNotFoundException, ValidationException):
            raise
        except Exception:
            logger.error(f"Failed to update audit report {report_id}", exc_info=True)
            raise BusinessLogicException(
                detail="Failed to update audit report",
                error_code="AUDIT_REPORT_UPDATE_FAILED",
                context={"report_id": report_id},
            )

    def generate_action_items(self, gaps: List[Any]) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for g in gaps:
            items.append({
                "title": f"Resolve: {getattr(g, 'gap_title', 'Gap')}",
                "due_in_days": 30 if str(getattr(g, 'risk_level', 'medium')) in ["critical", "high"] else 60,
                "gap_id": getattr(g, 'id', None),
                "owner": getattr(g, 'assigned_to', None),
            })
        return items

    async def generate_action_items(self, audit_session_id: str) -> str:
        """Generate AI action items for audit session based on compliance gaps and chat history."""
        try:
            import time
            from openai import OpenAI
            from config.config import settings
            
            start = time.time()
            
            # Fetch compliance gaps for the audit session
            compliance_gaps = await self.compliance_gap_repository.get_by_audit_session(audit_session_id)
            if not compliance_gaps:
                logger.info(f"No compliance gaps found for audit session {audit_session_id}")
                return "No compliance gaps identified for this audit session. No action items are needed at this time."
            
            # Fetch chat history for the audit session
            chat_history = await self.chat_history_repository.list_by_audit_session(audit_session_id, compliance_domain=None)
            
            # Group data by chat_history_id and compliance_gap
            grouped_data = []
            
            # Create a mapping of chat_history_id to chat messages
            chat_mapping = {}
            for chat in chat_history:
                chat_mapping[str(chat.id)] = {
                    'question': chat.question,
                    'answer': chat.answer,
                    'compliance_domain': chat.compliance_domain,
                    'created_at': chat.created_at.isoformat() if chat.created_at else None
                }
            
            # Group compliance gaps with their related chat history
            for gap in compliance_gaps:
                gap_data = {
                    'gap_id': gap.id,
                    'gap_title': getattr(gap, 'gap_title', 'Unknown Gap'),
                    'gap_description': getattr(gap, 'gap_description', ''),
                    'risk_level': getattr(gap, 'risk_level', 'medium'),
                    'recommendation': getattr(gap, 'recommendation_text', ''),
                    'recommended_actions': getattr(gap, 'recommended_actions', []),
                    'compliance_domain': getattr(gap, 'compliance_domain', ''),
                    'regulatory_requirement': getattr(gap, 'regulatory_requirement', False),
                    'assigned_to': getattr(gap, 'assigned_to', None),
                    'chat_history': None
                }
                
                # Find related chat history if available
                chat_history_id = getattr(gap, 'chat_history_id', None)
                if chat_history_id and str(chat_history_id) in chat_mapping:
                    gap_data['chat_history'] = chat_mapping[str(chat_history_id)]
                
                grouped_data.append(gap_data)
            
            # Prepare data for OpenAI query
            system_message = """You are an expert compliance project manager specializing in creating actionable checklist items for audit remediation. 
            Based on compliance gaps and related chat conversations, create detailed action items in checklist format that teams can execute to address the gaps.
            
            Your action items should be:
            - Specific, measurable, and actionable
            - Prioritized by risk level and regulatory requirements
            - Include clear success criteria and deadlines
            - Organized in logical implementation order
            - Include both immediate and follow-up actions
            - Consider resource requirements and dependencies
            - Professional and suitable for project management
            
            Format as a markdown checklist with clear categorization and success criteria for each item."""
            
            # Build the user prompt with all gap and chat data
            user_prompt = f"""
            Create detailed action items checklist for compliance gap remediation from audit session {audit_session_id}:

            ## Compliance Gaps and Context:
            """
            
            for i, item in enumerate(grouped_data, 1):
                user_prompt += f"""
                ### Gap {i}: {item['gap_title']} (Risk: {item['risk_level'].upper()})
                **Domain:** {item['compliance_domain']}
                **Regulatory:** {'Yes' if item['regulatory_requirement'] else 'No'}
                **Assigned To:** {item['assigned_to'] or 'Unassigned'}
                **Description:** {item['gap_description']}
                **Current Recommendation:** {item['recommendation'] or 'None provided'}
                **Suggested Actions:** {', '.join(item['recommended_actions']) if item['recommended_actions'] else 'None provided'}

                """
                if item['chat_history']:
                    user_prompt += f"""**Related Chat Context:**
                    - **Question:** {item['chat_history']['question']}
                    - **Answer:** {item['chat_history']['answer'][:400]}{'...' if len(item['chat_history']['answer']) > 400 else ''}
                    - **Date:** {item['chat_history']['created_at']}

                    """

            user_prompt += f"""
            ## Summary:
            - Total Gaps: {len(compliance_gaps)}
            - Critical/High Risk Gaps: {len([g for g in compliance_gaps if getattr(g, 'risk_level', 'medium') in ['critical', 'high']])}
            - Regulatory Gaps: {len([g for g in compliance_gaps if getattr(g, 'regulatory_requirement', False)])}
            - Chat Sessions Analyzed: {len([item for item in grouped_data if item['chat_history']])}

            ## Requirements:
            Create a comprehensive action items checklist organized by:

            1. **Immediate Actions (0-30 days)** - Critical and high-risk gaps requiring urgent attention
            2. **Short-term Actions (1-3 months)** - Medium-risk gaps and foundational improvements  
            3. **Long-term Actions (3-6 months)** - Process improvements and continuous monitoring

            For each action item, include:
            - Clear, specific task description
            - Success criteria (how to know it's complete)
            - Estimated timeline
            - Resource requirements
            - Dependencies (if any)
            - Verification method

            Format as markdown checklist with:
            - [ ] Action item description
            - **Success Criteria:** Specific measurable outcomes
            - **Timeline:** X days/weeks
            - **Owner:** Role/person responsible
            - **Resources:** What's needed
            - **Verification:** How to confirm completion

            Prioritize regulatory requirements and high-risk gaps first.
            """
            
            # Call OpenAI API
            client = OpenAI(api_key=settings.openai_api_key)
            
            completion = client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=3500,
            )
            
            action_items = completion.choices[0].message.content.strip()
            
            # Log performance
            log_performance(
                operation="generate_action_items",
                duration_ms=(time.time() - start) * 1000,
                success=True,
                item_count=len(compliance_gaps),
            )
            
            logger.info(f"Successfully generated action items for audit session {audit_session_id} with {len(compliance_gaps)} gaps")
            
            # Return action items with metadata
            return {
                'action_items': action_items,
                'gaps_analyzed': len(compliance_gaps),
                'chat_sessions_analyzed': len([item for item in grouped_data if item['chat_history']]),
                'regulatory_gaps': len([g for g in compliance_gaps if getattr(g, 'regulatory_requirement', False)]),
                'critical_high_risk_gaps': len([g for g in compliance_gaps if getattr(g, 'risk_level', 'medium') in ['critical', 'high']])
            }
            
        except Exception as e:
            logger.error(f"Failed to generate action items for audit session {audit_session_id}: {str(e)}", exc_info=True)
            raise BusinessLogicException(
                detail=f"Failed to generate action items: {str(e)}",
                error_code="ACTION_ITEMS_GENERATION_FAILED",
                context={"audit_session_id": audit_session_id},
            )

    def _deserialize_report_fields(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Deserialize JSON string fields back to formatted strings for frontend compatibility."""
        if not report:
            return report
            
        report_copy = report.copy()
        
        # Deserialize recommendations from JSON string and format as string for frontend
        recommendations = report_copy.get("recommendations")
        if isinstance(recommendations, str):
            try:
                parsed_recommendations = json.loads(recommendations)
                if isinstance(parsed_recommendations, list) and parsed_recommendations:
                    # Format as numbered list for frontend compatibility
                    formatted_items = []
                    for i, item in enumerate(parsed_recommendations, 1):
                        formatted_items.append(f"{i}. {item}")
                    report_copy["recommendations"] = "\n".join(formatted_items)
                else:
                    report_copy["recommendations"] = ""
            except (json.JSONDecodeError, ValueError):
                logger.warning(f"Failed to deserialize recommendations JSON: {recommendations}")
                report_copy["recommendations"] = ""
        
        # Deserialize action_items from JSON string and format as string for frontend
        action_items = report_copy.get("action_items")
        if isinstance(action_items, str):
            try:
                parsed_action_items = json.loads(action_items)
                if isinstance(parsed_action_items, list) and parsed_action_items:
                    # Format as numbered list for frontend compatibility
                    formatted_items = []
                    for i, item in enumerate(parsed_action_items, 1):
                        formatted_items.append(f"{i}. {item}")
                    report_copy["action_items"] = "\n".join(formatted_items)
                else:
                    report_copy["action_items"] = ""
            except (json.JSONDecodeError, ValueError):
                logger.warning(f"Failed to deserialize action_items JSON: {action_items}")
                report_copy["action_items"] = ""
        
        return report_copy

    async def generate_recommendations(self, audit_session_id: str) -> str:
        """Generate AI recommendations for audit session based on compliance gaps and chat history."""
        try:
            import time
            from openai import OpenAI
            from config.config import settings
            
            start = time.time()
            
            # Fetch compliance gaps for the audit session
            compliance_gaps = await self.compliance_gap_repository.get_by_audit_session(audit_session_id)
            if not compliance_gaps:
                logger.info(f"No compliance gaps found for audit session {audit_session_id}")
                return "No compliance gaps identified for this audit session. No specific recommendations are needed at this time."
            
            # Fetch chat history for the audit session
            chat_history = await self.chat_history_repository.list_by_audit_session(audit_session_id, compliance_domain=None)
            
            # Group data by chat_history_id and compliance_gap
            grouped_data = []
            
            # Create a mapping of chat_history_id to chat messages
            chat_mapping = {}
            for chat in chat_history:
                chat_mapping[str(chat.id)] = {
                    'question': chat.question,
                    'answer': chat.answer,
                    'compliance_domain': chat.compliance_domain,
                    'created_at': chat.created_at.isoformat() if chat.created_at else None
                }
            
            # Group compliance gaps with their related chat history
            for gap in compliance_gaps:
                gap_data = {
                    'gap_id': gap.id,
                    'gap_title': getattr(gap, 'gap_title', 'Unknown Gap'),
                    'gap_description': getattr(gap, 'gap_description', ''),
                    'risk_level': getattr(gap, 'risk_level', 'medium'),
                    'recommendation': getattr(gap, 'recommendation_text', ''),
                    'compliance_domain': getattr(gap, 'compliance_domain', ''),
                    'chat_history': None
                }
                
                # Find related chat history if available
                chat_history_id = getattr(gap, 'chat_history_id', None)
                if chat_history_id and str(chat_history_id) in chat_mapping:
                    gap_data['chat_history'] = chat_mapping[str(chat_history_id)]
                
                grouped_data.append(gap_data)
            
            # Prepare data for OpenAI query
            system_message = """You are an expert compliance analyst specializing in generating actionable recommendations for audit reports. 
            Based on compliance gaps identified during an audit session and the related chat conversations, provide comprehensive, 
            practical recommendations that address the specific gaps and improve overall compliance posture.
            
            Your recommendations should be:
            - Specific and actionable
            - Prioritized by risk level
            - Grouped by compliance domain when applicable
            - Include both immediate and long-term actions
            - Consider the context from chat conversations
            - Professional and suitable for audit report inclusion"""
            
            # Build the user prompt with all gap and chat data
            user_prompt = f"""
            Analyze the following compliance gaps and related chat history from audit session {audit_session_id} and generate comprehensive recommendations:

            ## Compliance Gaps and Related Context:
            """
            
            for i, item in enumerate(grouped_data, 1):
                user_prompt += f"""
                ### Gap {i}: {item['gap_title']} (Risk: {item['risk_level'].upper()})
                **Domain:** {item['compliance_domain']}
                **Description:** {item['gap_description']}
                **Existing Recommendation:** {item['recommendation'] or 'None provided'}

                """
                if item['chat_history']:
                    user_prompt += f"""**Related Chat Context:**
                    - **Question:** {item['chat_history']['question']}
                    - **Answer:** {item['chat_history']['answer'][:500]}{'...' if len(item['chat_history']['answer']) > 500 else ''}
                    - **Date:** {item['chat_history']['created_at']}

                    """

            user_prompt += f"""
            ## Summary:
            - Total Gaps: {len(compliance_gaps)}
            - High/Critical Risk Gaps: {len([g for g in compliance_gaps if getattr(g, 'risk_level', 'medium') in ['high', 'critical']])}
            - Chat Sessions Analyzed: {len([item for item in grouped_data if item['chat_history']])}

            ## Requirements:
            Generate a comprehensive recommendations report that:
            1. **Executive Summary** - Overview of key recommendations
            2. **Priority Actions** - Immediate actions for high/critical risk gaps
            3. **Implementation Roadmap** - Medium-term actions with timeline
            4. **Process Improvements** - Long-term systematic improvements
            5. **Monitoring & Follow-up** - How to track progress and ensure compliance

            Format the response in clear markdown suitable for inclusion in an audit report.
            """
            
            # Call OpenAI API
            client = OpenAI(api_key=settings.openai_api_key)
            
            completion = client.chat.completions.create(
                model=settings.openai_model,
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=3000,
            )
            
            recommendations = completion.choices[0].message.content.strip()
            
            # Log performance
            log_performance(
                operation="generate_recommendations",
                duration_ms=(time.time() - start) * 1000,
                success=True,
                item_count=len(compliance_gaps),
            )
            
            logger.info(f"Successfully generated recommendations for audit session {audit_session_id} with {len(compliance_gaps)} gaps")
            
            # Return recommendations with metadata
            return {
                'recommendations': recommendations,
                'gaps_analyzed': len(compliance_gaps),
                'chat_sessions_analyzed': len([item for item in grouped_data if item['chat_history']]),
                'high_risk_gaps': len([g for g in compliance_gaps if getattr(g, 'risk_level', 'medium') in ['high', 'critical']])
            }
            
        except Exception as e:
            logger.error(f"Failed to generate recommendations for audit session {audit_session_id}: {str(e)}", exc_info=True)
            raise BusinessLogicException(
                detail=f"Failed to generate recommendations: {str(e)}",
                error_code="RECOMMENDATIONS_GENERATION_FAILED",
                context={"audit_session_id": audit_session_id},
            )

def create_audit_report_service(
    report_repository: AuditReportRepository,
    user_repository: UserRepository,
    chat_history_repository: ChatHistoryRepository,
    compliance_gap_repository: ComplianceGapRepository,
    audit_session_repository: AuditSessionRepository,
) -> AuditReportService:
    return AuditReportService(
        report_repository,
        user_repository,
        chat_history_repository,
        compliance_gap_repository,
        audit_session_repository,
    )
