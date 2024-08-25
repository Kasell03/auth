from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
from redis import asyncio as aioredis, Redis
from src.config import AUTH_REDIS_PORT


__redis_app: Redis | None = None

async def init_redis():
    global __redis_app
    __redis_app = await aioredis.from_url(f"redis://localhost:{AUTH_REDIS_PORT}", encoding="utf-8", decode_responses=True)
    FastAPICache.init(RedisBackend(__redis_app), prefix="fastapi-cache")

    return __redis_app

async def get_value(key: str) -> str | int | None:
    if not __redis_app:
        return None

    key = await __redis_app.get(key)

    if not key:
        return None

    return key

async def set_value(key: str, value: str | int, ex_time: int = None):
    if not __redis_app:
        return None

    await __redis_app.set(name=key, value=value, ex=ex_time)

async def del_value(key: str):
    if not __redis_app:
        return None

    await __redis_app.dump(name=key)