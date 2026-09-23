"""Database engine, connection pooling, and session lifecycle management."""

import logging
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    """Retrieve or initialize the singleton asynchronous SQLAlchemy engine."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.DATABASE_URL,
            pool_size=settings.DATABASE_POOL_SIZE,
            max_overflow=settings.DATABASE_MAX_OVERFLOW,
            pool_timeout=settings.DATABASE_POOL_TIMEOUT,
            echo=settings.DATABASE_ECHO,
            future=True,
        )
        logger.info("Initialized asynchronous PostgreSQL engine pool.")
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Retrieve or initialize the sessionmaker for asynchronous DB sessions."""
    global _session_factory
    if _session_factory is None:
        engine = get_engine()
        _session_factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
    return _session_factory


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an isolated async database session."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_db_connections() -> None:
    """Dispose of the database connection engine pool on application shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        logger.info("Disposing PostgreSQL connection pool.")
        await _engine.dispose()
        _engine = None
        _session_factory = None
