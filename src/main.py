from fastapi import FastAPI
from .auth.router import user_router
from .redis import init_redis
from src.config import BASE_DIR, settings

app = FastAPI()

@app.get('/')
def home():

    return 'Home page'


app.include_router(user_router, prefix=f"{settings.API_PATH}/auth", tags=["Auth"])


@app.on_event("startup")
async def startup_event():
    await init_redis()

