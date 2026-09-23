"""SQLAlchemy Declarative Base model."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models in TunnelTrace AI."""

    pass


# Ensure all declarative models are registered on Base.metadata
import app.db.models  # noqa: E402, F401
