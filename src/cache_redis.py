from fastapi_cache import FastAPICache
from src.config import AUTH_REDIS_PORT
from redis import asyncio as aioredis, Redis
from fastapi_cache.backends.redis import RedisBackend


class CacheRedis:
    def __init__(self):
        self.__redis_app: Redis | None = None
        self.__is_initialized = False

    async def init_redis(self, host: str, port: int):
        if self.__is_initialized is False:
            self.__redis_app = await aioredis.from_url(f"redis://{host}:{port}", encoding="utf-8",
                                                       decode_responses=True)
            FastAPICache.init(RedisBackend(self.__redis_app), prefix="fastapi-cache")
            self.__is_initialized = True

    async def get_value(self, key: str) -> str | int | None:
        if not self.__redis_app:
            return None

        key = await self.__redis_app.get(key)

        if not key:
            return None

        return key

    async def set_value(self, key: str, value: str | int, ex_time_sec: int = None):
        if not self.__redis_app:
            return None

        await self.__redis_app.set(name=key, value=value, ex=ex_time_sec)

    async def del_value(self, key: str):
        if not self.__redis_app:
            return None

        await self.__redis_app.delete(key)

    async def close_session(self):
        await self.__redis_app.close()