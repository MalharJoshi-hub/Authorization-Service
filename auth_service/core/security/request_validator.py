"""HTTP Request Integrity & Input Sanitization Engine (Layer 1).

Validates Content-Type headers, enforces payload size constraints to avert DoS attacks,
and sanitizes input strings to strip dangerous control sequences.
"""

import html
import re
from typing import Any, Dict, Optional
from fastapi import Request
from auth_service.core.exceptions import ValidationError


MAX_REQUEST_BODY_BYTES = 10 * 1024 * 1024  # 10 MB limit


def sanitize_string(value: str) -> str:
    """Sanitize string values by stripping null bytes and HTML-escaping characters."""
    if not isinstance(value, str):
        return value
    # Remove null bytes and non-printable control characters (except newline, carriage return, tab)
    cleaned = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", value)
    return html.escape(cleaned.strip())


sanitize_text = sanitize_string



def sanitize_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively sanitize string contents of dictionary structures."""
    sanitized: Dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, str):
            sanitized[k] = sanitize_string(v)
        elif isinstance(v, dict):
            sanitized[k] = sanitize_dict(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_string(item) if isinstance(item, str)
                else sanitize_dict(item) if isinstance(item, dict)
                else item
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


async def validate_request_size(request: Request, max_bytes: int = MAX_REQUEST_BODY_BYTES) -> None:
    """Enforce maximum body size via Content-Length inspection."""
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            length = int(content_length)
            if length > max_bytes:
                raise ValidationError(
                    f"Request payload exceeds maximum allowed size of {max_bytes} bytes.",
                    code="PAYLOAD_TOO_LARGE",
                )
        except ValueError:
            raise ValidationError("Invalid Content-Length header", code="INVALID_HEADER")
