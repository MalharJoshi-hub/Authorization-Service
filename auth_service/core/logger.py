"""Structured Logging Subsystem.

Provides JSON-formatted logs with request correlation IDs, ISO 8601 timestamps,
and execution context for enterprise observability.
"""

import logging
import json
import sys
from datetime import datetime, timezone
from contextvars import ContextVar
from typing import Any, Dict, Optional

# Context variable to hold request correlation ID across async tasks
request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id_ctx", default=None)
tenant_id_ctx: ContextVar[Optional[str]] = ContextVar("tenant_id_ctx", default=None)


class JSONLogFormatter(logging.Formatter):
    """Custom formatter producing compact JSON output per log record."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "func": record.funcName,
            "line": record.lineno,
        }

        # Inject context variables
        req_id = request_id_ctx.get()
        if req_id:
            log_obj["request_id"] = req_id

        t_id = tenant_id_ctx.get()
        if t_id:
            log_obj["tenant_id"] = t_id

        # Attach exception trace if available
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        # Attach custom extra fields if passed
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_obj.update(record.extra_data)

        return json.dumps(log_obj)


def setup_logger(name: str = "aas", level: str = "INFO") -> logging.Logger:
    """Configure and return a structured logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Prevent double-attaching handlers if already set up
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONLogFormatter())
        logger.addHandler(handler)
        logger.propagate = False

    return logger


logger = setup_logger()
get_logger = setup_logger
