import asyncio
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool
import pytest
from fastapi.testclient import TestClient

from src.main import app
from src.config import TEST_DB_HOST, TEST_DB_NAME, TEST_DB_PASS, TEST_DB_PORT, TEST_DB_USER, TEST_AUTH_REDIS_PORT, TEST_AUTH_REDIS_HOST
from src.database import get_async_session, Base
from src.auth.router import cache_redis


DATABASE_URL_TEST = f"postgresql+asyncpg://{TEST_DB_USER}:{TEST_DB_PASS}@{TEST_DB_HOST}:{TEST_DB_PORT}/{TEST_DB_NAME}"

engine_test = create_async_engine(DATABASE_URL_TEST, poolclass=NullPool)
async_session_maker = async_sessionmaker(engine_test)
Base.metadata.bind = engine_test

async def override_get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session

app.dependency_overrides[get_async_session] = override_get_async_session

@pytest.fixture(autouse=True, scope="session")
async def prepare_test_database():
    async with engine_test.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine_test.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(autouse=True, scope="session")
async def connect_test_redis():
    await cache_redis.init_redis(host=TEST_AUTH_REDIS_HOST, port=TEST_AUTH_REDIS_PORT)

@pytest.fixture(autouse=True, scope="session")
async def check_test_db():
    async with async_session_maker() as session:
        db_name = await session.execute(text("SELECT current_database()"))

    assert db_name.scalar_one() == "test_auth"

client = TestClient(app)
transport = ASGITransport(app=app)

@pytest.fixture(scope="session")
async def ac() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


