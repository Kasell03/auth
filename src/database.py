from typing import Annotated, AsyncGenerator

from fastapi import Depends

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import String

from src.config import DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME


DATABASE_URL = f"postgresql+asyncpg://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


engine = create_async_engine(DATABASE_URL)
async_session_maker = async_sessionmaker(engine)


str_32 = Annotated[str, 32]
str_64 = Annotated[str, 64]
str_128 = Annotated[str, 128]
str_256 = Annotated[str, 256]
str_512 = Annotated[str, 512]


class Base(DeclarativeBase):
    type_annotation_map = {
        str_32: String(32),
        str_64: String(64),
        str_128: String(128),
        str_256: String(256),
        str_512: String(512),
    }


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session
