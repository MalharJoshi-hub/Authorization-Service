"""Central Domain Exceptions for Auth-as-a-Service.

Defines standardized exceptions mapped to appropriate HTTP status codes and
structured error responses.
"""

from typing import Any, Dict, Optional
from fastapi import HTTPException, status


class AaaSException(Exception):
    """Base exception for all Auth-as-a-Service domain errors."""

    def __init__(self, message: str, code: str = "INTERNAL_ERROR", details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}


class AuthenticationError(AaaSException):
    """Raised when authentication fails (invalid credentials, expired token, etc.)."""

    def __init__(self, message: str = "Authentication failed", code: str = "AUTH_FAILED", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code=code, details=details)


class AuthorizationError(AaaSException):
    """Raised when a user lacks required permissions or roles."""

    def __init__(self, message: str = "Insufficient permissions", code: str = "FORBIDDEN", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code=code, details=details)


class ResourceNotFoundError(AaaSException):
    """Raised when a requested resource is not found."""

    def __init__(self, message: str = "Resource not found", code: str = "NOT_FOUND", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code=code, details=details)


class ConflictError(AaaSException):
    """Raised when creating a resource that violates a unique constraint (e.g. duplicate email)."""

    def __init__(self, message: str = "Resource conflict", code: str = "CONFLICT", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code=code, details=details)


class ValidationError(AaaSException):
    """Raised when input validation fails."""

    def __init__(self, message: str = "Validation failed", code: str = "VALIDATION_ERROR", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code=code, details=details)


class RateLimitExceededError(AaaSException):
    """Raised when request frequency exceeds allocated quota."""

    def __init__(self, message: str = "Rate limit exceeded", code: str = "RATE_LIMIT_EXCEEDED", retry_after: int = 60):
        super().__init__(message, code=code, details={"retry_after": retry_after})
        self.retry_after = retry_after


class AccountLockedError(AaaSException):
    """Raised when an account is locked due to consecutive failed login attempts."""

    def __init__(self, message: str = "Account temporarily locked due to excessive failed attempts", lockout_minutes: int = 15):
        super().__init__(message, code="ACCOUNT_LOCKED", details={"lockout_minutes": lockout_minutes})
        self.lockout_minutes = lockout_minutes


class TokenBlacklistedError(AuthenticationError):
    """Raised when an access token has been explicitly revoked or blacklisted."""

    def __init__(self, message: str = "Token has been revoked"):
        super().__init__(message, code="TOKEN_REVOKED")


class TokenReuseDetectedError(AuthenticationError):
    """Raised when a rotated refresh token is submitted more than once."""

    def __init__(self, message: str = "Refresh token reuse detected. All sessions invalidated for security."):
        super().__init__(message, code="TOKEN_REUSE_DETECTED")


def to_http_exception(exc: AaaSException) -> HTTPException:
    """Translate domain exceptions into standardized FastAPI HTTPExceptions."""
    if isinstance(exc, AuthenticationError):
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": exc.code, "message": exc.message, "details": exc.details},
            headers={"WWW-Authenticate": "Bearer"},
        )
    if isinstance(exc, AuthorizationError):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": exc.code, "message": exc.message, "details": exc.details},
        )
    if isinstance(exc, ResourceNotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": exc.code, "message": exc.message, "details": exc.details},
        )
    if isinstance(exc, ConflictError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": exc.code, "message": exc.message, "details": exc.details},
        )
    if isinstance(exc, RateLimitExceededError):
        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"error": exc.code, "message": exc.message, "details": exc.details},
            headers={"Retry-After": str(exc.retry_after)},
        )
    if isinstance(exc, ValidationError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": exc.code, "message": exc.message, "details": exc.details},
        )
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={"error": exc.code, "message": exc.message, "details": exc.details},
    )
