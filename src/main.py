from contextlib import asynccontextmanager
from fastapi import FastAPI
from .auth.router import user_router, cache_redis
from .cache_redis import CacheRedis
from src.config import BASE_DIR, settings, AUTH_REDIS_PORT, AUTH_REDIS_HOST


@asynccontextmanager
async def lifespan(application: FastAPI):
    # await init_redis(host=AUTH_REDIS_HOST, port=AUTH_REDIS_PORT)
    await cache_redis.init_redis(host=AUTH_REDIS_HOST, port=AUTH_REDIS_PORT)
    yield


app = FastAPI(lifespan=lifespan)

@app.get('/')
def home():

    return 'Home page'


app.include_router(user_router, prefix=f"{settings.API_PATH}/auth", tags=["Auth"])


