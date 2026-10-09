"""SQLAlchemy Declarative Base and Reusable Mixins (Layer 4).

Provides standard UUID primary keys, UTC timestamp auditing, and serialization helpers.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import Column, DateTime, String
from sqlalchemy.orm import declarative_base, declared_attr


Base = declarative_base()


class UUIDPrimaryKeyMixin:
    """Provides a standardized string UUID primary key column."""

    @declared_attr
    def id(cls):
        return Column(
            String(36),
            primary_key=True,
            default=lambda: str(uuid.uuid4()),
            index=True,
            nullable=False,
        )


class TimestampMixin:
    """Injects UTC-aware creation and modification timestamps."""

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class ModelSerializerMixin:
    """Provides automated dictionary serialization of model attributes."""

    def to_dict(self) -> Dict[str, Any]:
        """Convert model attributes to a JSON-serializable dictionary."""
        result = {}
        for col in self.__table__.columns:
            val = getattr(self, col.name)
            if isinstance(val, datetime):
                result[col.name] = val.isoformat()
            else:
                result[col.name] = val
        return result
