"""Common Response Envelopes & Pagination Schemas (Layer 5: API).

Standardizes successful response wrappers, paginated collections, and error representations.
"""

from typing import Any, Dict, Generic, List, Optional, TypeVar
from pydantic import BaseModel, Field


T = TypeVar("T")


class MessageResponse(BaseModel):
    """Standard generic acknowledgement response."""

    message: str
    success: bool = True
    details: Optional[Dict[str, Any]] = None


class ErrorDetail(BaseModel):
    """Structured error descriptor."""

    error: str
    message: str
    details: Optional[Dict[str, Any]] = Field(default_factory=dict)


class PaginatedResponse(BaseModel, Generic[T]):
    """Standardized paginated list envelope."""

    items: List[T]
    total: int
    skip: int
    limit: int
    pages: int

    @classmethod
    def create(cls, items: List[T], total: int, skip: int, limit: int):
        pages = (total + limit - 1) // limit if limit > 0 else 1
        return cls(
            items=items,
            total=total,
            skip=skip,
            limit=limit,
            pages=pages,
        )
