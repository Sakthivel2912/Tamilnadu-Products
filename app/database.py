from collections.abc import AsyncGenerator
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .db.models import Base

_engine = None
_async_session_maker = None


def get_sqlite_url(settings: dict) -> str:
    path = Path(settings["sqlite_path"]).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{path.as_posix()}"


def configure_engine(settings: dict) -> None:
    global _engine, _async_session_maker
    url = settings["sqlite_url"] or get_sqlite_url(settings)
    _engine = create_async_engine(url, echo=False)
    _async_session_maker = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


def get_engine():
    if _engine is None:
        raise RuntimeError("Database not configured.")
    return _engine


async def init_db() -> None:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    if _async_session_maker is None:
        raise RuntimeError("Database not configured.")
    async with _async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
