import re
import logging
from typing import List, Optional
import unicodedata
import bleach
from fastapi import HTTPException
from pydantic import validator

logger = logging.getLogger(__name__)

class SecurityError(Exception):
    pass

SECRET_PATS = [
    re.compile(r'\bsk-[A-Za-z0-9]{20,}\b'),              # generic "sk-" keys
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),                 # AWS access key
    re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'),           # Google API key
    re.compile(r'\b\d{16}\b'),                           # naive card (tighten in prod)
    re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', re.I),  # emails
]

def redact(text: str) -> str:
    for pat in SECRET_PATS:
        text = pat.sub("[redacted]", text)
    return text

def safe_stream(upstream_iter):
    TAIL = 96
    tail = ""
    for chunk in upstream_iter:
        chunk = str(chunk).replace("\x00", "")
        merged = tail + chunk
        redacted = redact(merged)
        yield redacted[len(tail):]
        tail = redacted[-TAIL:]

class InputValidator:
    BLOCKED_PATTERNS = [
        r'<script[^>]*>.*?</script>',  # JavaScript
        r'javascript:',  # JavaScript protocol
        r'data:text/html',  # Data URLs with HTML
        r'vbscript:',  # VBScript
        r'on\w+\s*=',  # Event handlers
        r'expression\s*\(',  # CSS expressions
        r'\\x[0-9a-fA-F]{2}',  # Hex encoded chars
        r'\\u[0-9a-fA-F]{4}',  # Unicode encoded chars
    ]
    
    # Prompt injection patterns
    PROMPT_INJECTION_PATTERNS = [
        r'ignore\s+previous\s+instructions',
        r'forget\s+everything',
        r'system\s*:',
        r'assistant\s*:',
        r'human\s*:',
        r'user\s*:',
        r'prompt\s*:',
        r'###\s*instruction',
        r'###\s*system',
        r'<\|system\|>',
        r'<\|user\|>',
        r'<\|assistant\|>',
        r'jailbreak',
        r'roleplay\s+as',
        r'pretend\s+to\s+be',
        r'act\s+as\s+if',
        r'simulate\s+being',
    ]
    
    INVIS = {0x200B: None, 0x200C: None, 0x200D: None, 0x2060: None, 0xFEFF: None}  # ZWSP/ZWNJ/ZWJ/WJ/BOM
    
    def strip_invisible(s: str) -> str:
        return s.translate(InputValidator.INVIS)

    @staticmethod
    def sanitize_text(text: str, max_length: Optional[int] = None) -> str:
        if not isinstance(text, str):
            raise SecurityError("Input must be a string")
        
        if max_length and len(text) > max_length:
            raise SecurityError(f"Input exceeds maximum length of {max_length}")
        
        text = unicodedata.normalize("NFKC", text)
        text = InputValidator.strip_invisible(text)

        cleaned_text = bleach.clean(
            text,
            tags=[],
            attributes={},
            strip=True
        )

        for pattern in InputValidator.BLOCKED_PATTERNS:
            if re.search(pattern, cleaned_text, re.IGNORECASE):
                logger.warning(f"Blocked pattern detected: {pattern}")
                raise SecurityError("Input contains potentially malicious content")
        
        return cleaned_text.strip()
    
    @staticmethod
    def validate_question(question: str) -> str:
        if not question or not question.strip():
            raise SecurityError("Question cannot be empty")

        if len(question) > 2000:
            raise SecurityError("Question too long (max 2000 characters)")
        
        sanitized = InputValidator.sanitize_text(question, 2000)

        for pattern in InputValidator.PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, sanitized, re.IGNORECASE):
                logger.warning(f"Potential prompt injection detected: {pattern}")
                raise SecurityError("Question contains potentially malicious instructions")

        if len(sanitized.split()) < 3:
            raise SecurityError("Question must contain at least 3 words")
        
        return sanitized
    
    @staticmethod
    def validate_compliance_domain(domain: str) -> str:
        if not domain:
            return domain
            
        domain = InputValidator.sanitize_text(domain, 100)
        
        valid_domains = {
            "GDPR", "ISO27001", "ISO9001",
        }
        
        if domain.upper() not in valid_domains:
            raise SecurityError(f"Unknown compliance domain: {domain}")
            
        return domain.upper()
    
    @staticmethod
    def validate_tags(tags: List[str]) -> List[str]:
        if not tags:
            return tags

        if len(tags) > 10:
            tags = tags[:10]
            
        validated_tags = []
        for tag in tags:
            try:
                clean_tag = InputValidator.sanitize_text(str(tag), 50)
                if clean_tag:
                    validated_tags.append(clean_tag)
            except SecurityError:
                continue 
                
        return validated_tags

from datetime import datetime, timedelta
from collections import defaultdict

class SimpleRateLimiter:    
    def __init__(self, max_requests: int = 30, window_minutes: int = 1):
        self.max_requests = max_requests
        self.window_minutes = window_minutes
        self.requests = defaultdict(list)
    
    def is_allowed(self, client_id: str) -> bool:
        now = datetime.now()
        window_start = now - timedelta(minutes=self.window_minutes)

        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if req_time > window_start
        ]

        if len(self.requests[client_id]) >= self.max_requests:
            return False

        self.requests[client_id].append(now)
        return True

rate_limiter = SimpleRateLimiter(max_requests=30, window_minutes=1)

from services.schemas import QueryRequest
from fastapi import Request

def validate_and_secure_query_request(req: QueryRequest, request: Request) -> QueryRequest:
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.is_allowed(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please try again later.")
    
    try:
        req.question = InputValidator.validate_question(req.question)
        if req.conversation_id:
            import uuid
            try:
                uuid.UUID(req.conversation_id)
            except ValueError:
                raise SecurityError("Invalid conversation_id format - must be UUID")
        
        if req.audit_session_id:
            import uuid
            try:
                uuid.UUID(req.audit_session_id)
            except ValueError:
                raise SecurityError("Invalid audit_session_id format - must be UUID")

        if req.compliance_domain:
            req.compliance_domain = InputValidator.validate_compliance_domain(req.compliance_domain)

        if req.user_id:
            req.user_id = InputValidator.sanitize_text(req.user_id, 100)

        if req.document_versions:
            if isinstance(req.document_versions, list):
                req.document_versions = [InputValidator.sanitize_text(version, 50) for version in req.document_versions]
            else:
                req.document_versions = [InputValidator.sanitize_text(req.document_versions, 50)]

        if req.document_tags:
            req.document_tags = InputValidator.validate_tags(req.document_tags)
        
        return req
        
    except SecurityError as e:
        logger.warning(f"Security validation failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected validation error: {e}")
        raise HTTPException(status_code=400, detail="Request validation failed")