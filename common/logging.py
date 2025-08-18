"""
Structured logging configuration for the RAG application.
Provides correlation IDs, structured JSON logging, and proper error tracking.
"""

import logging
import sys
import uuid
from typing import Optional, Dict, Any
from contextvars import ContextVar
from datetime import datetime, timezone

# Context variables for request tracking
request_id_var: ContextVar[Optional[str]] = ContextVar('request_id', default=None)
user_id_var: ContextVar[Optional[str]] = ContextVar('user_id', default=None)
audit_session_var: ContextVar[Optional[str]] = ContextVar('audit_session', default=None)


class StructuredFormatter(logging.Formatter):
    """Custom formatter that outputs structured JSON logs."""
    
    def format(self, record: logging.LogRecord) -> str:
        # Build base log entry
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add request context if available
        request_id = request_id_var.get()
        if request_id:
            log_entry["request_id"] = request_id
            
        user_id = user_id_var.get()
        if user_id:
            log_entry["user_id"] = user_id
            
        audit_session = audit_session_var.get()
        if audit_session:
            log_entry["audit_session_id"] = audit_session
        
        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": self.formatException(record.exc_info)
            }
        
        # Add any extra fields from the log record
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 
                          'filename', 'module', 'exc_info', 'exc_text', 'stack_info',
                          'lineno', 'funcName', 'created', 'msecs', 'relativeCreated',
                          'thread', 'threadName', 'processName', 'process', 'getMessage']:
                log_entry[key] = value
        
        return self._serialize_log_entry(log_entry)
    
    def _serialize_log_entry(self, log_entry: Dict[str, Any]) -> str:
        """Serialize log entry to JSON string."""
        import json
        try:
            return json.dumps(log_entry, default=str, ensure_ascii=False)
        except (TypeError, ValueError) as e:
            # Fallback to basic logging if JSON serialization fails
            return f"LOG_SERIALIZATION_ERROR: {e} | Original message: {log_entry.get('message', 'N/A')}"


class RequestContextLogger:
    """Context manager for setting request-specific logging context."""
    
    def __init__(
        self,
        request_id: Optional[str] = None,
        user_id: Optional[str] = None,
        audit_session_id: Optional[str] = None
    ):
        self.request_id = request_id or str(uuid.uuid4())
        self.user_id = user_id
        self.audit_session_id = audit_session_id
        self.tokens = []
    
    def __enter__(self):
        self.tokens.append(request_id_var.set(self.request_id))
        if self.user_id:
            self.tokens.append(user_id_var.set(self.user_id))
        if self.audit_session_id:
            self.tokens.append(audit_session_var.set(self.audit_session_id))
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        for token in reversed(self.tokens):
            if token:
                token.var.reset(token)


def setup_logging(
    level: str = "INFO",
    format_type: str = "structured",
    log_file: Optional[str] = None
) -> None:
    """
    Setup application logging configuration.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_type: Format type ('structured' for JSON, 'simple' for readable)
        log_file: Optional file path for logging output
    """
    # Clear any existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Set logging level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)
    
    # Create formatter based on type
    if format_type == "structured":
        formatter = StructuredFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Setup console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Setup file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Reduce noise from external libraries
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("fastapi").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the specified name."""
    return logging.getLogger(name)


def log_performance(
    operation: str,
    duration_ms: float,
    success: bool = True,
    **kwargs
) -> None:
    """Log performance metrics for operations."""
    logger = get_logger("performance")
    logger.info(
        f"Performance metric: {operation}",
        extra={
            "operation": operation,
            "duration_ms": duration_ms,
            "success": success,
            **kwargs
        }
    )


def log_security_event(
    event_type: str,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """Log security-related events."""
    logger = get_logger("security")
    logger.warning(
        f"Security event: {event_type}",
        extra={
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": ip_address,
            "details": details or {}
        }
    )


def log_business_event(
    event_type: str,
    entity_type: str,
    entity_id: str,
    action: str,
    user_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> None:
    """Log business-related events."""
    logger = get_logger("business")
    logger.info(
        f"Business event: {event_type}",
        extra={
            "event_type": event_type,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "action": action,
            "user_id": user_id,
            "details": details or {}
        }
    )


def log_api_request(
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    user_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> None:
    """Log API request details."""
    logger = get_logger("api")
    logger.info(
        f"API request: {method} {path}",
        extra={
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration_ms": duration_ms,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent
        }
    )


def log_error(
    error: Exception,
    context: Optional[Dict[str, Any]] = None,
    user_id: Optional[str] = None
) -> None:
    """Log error with context information."""
    logger = get_logger("error")
    
    error_context = {
        "error_type": type(error).__name__,
        "error_message": str(error),
        "user_id": user_id,
        **(context or {})
    }
    
    # Add custom exception context if available
    if hasattr(error, 'context'):
        error_context["exception_context"] = error.context
    if hasattr(error, 'error_code'):
        error_context["error_code"] = error.error_code
    
    logger.error(
        f"Error occurred: {type(error).__name__}",
        extra=error_context,
        exc_info=True
    )