import datetime
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
import os

from fastapi_mail import ConnectionConfig
from pydantic_settings import BaseSettings

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../'))

load_dotenv()

DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASS = os.environ.get("DB_PASS")
DB_HOST = os.environ.get("DB_HOST")
DB_PORT = os.environ.get("DB_PORT")

TEST_DB_NAME = os.environ.get("TEST_DB_NAME")
TEST_DB_USER = os.environ.get("TEST_DB_USER")
TEST_DB_PASS = os.environ.get("TEST_DB_PASS")
TEST_DB_HOST = os.environ.get("TEST_DB_HOST")
TEST_DB_PORT = os.environ.get("TEST_DB_PORT")

MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
MAIL_FROM = os.environ.get("MAIL_FROM")
MAIL_PORT = os.environ.get("MAIL_PORT")
MAIL_SERVER = os.environ.get("MAIL_SERVER")
MAIL_FROM_NAME = os.environ.get("MAIL_FROM_NAME")

HASH_ALGORITHM = os.environ.get("ALGORITHM")

AUTH_REDIS_HOST = os.environ.get("AUTH_REDIS_HOST")
AUTH_REDIS_PORT = os.environ.get("AUTH_REDIS_PORT")
TEST_AUTH_REDIS_HOST = os.environ.get("TEST_AUTH_REDIS_HOST")
TEST_AUTH_REDIS_PORT = os.environ.get("TEST_AUTH_REDIS_PORT")

email_connection_config = ConnectionConfig(
                MAIL_USERNAME=MAIL_USERNAME,
                MAIL_PASSWORD=MAIL_PASSWORD,
                MAIL_FROM=MAIL_FROM,
                MAIL_PORT=MAIL_PORT,
                MAIL_SERVER=MAIL_SERVER,
                MAIL_FROM_NAME=MAIL_FROM_NAME,
                MAIL_STARTTLS=True,
                MAIL_SSL_TLS=False,
                USE_CREDENTIALS=True,
            )

class AuthJWT(BaseSettings):
    private_key_path: Path = BASE_DIR + "/certs/jwt-private.pem"
    public_key_path: Path = BASE_DIR + "/certs/jwt-public.pem"
    algorithm: str = HASH_ALGORITHM
    access_token_life_time: datetime.timedelta = datetime.timedelta(minutes=15)
    refresh_token_life_time: datetime.timedelta = datetime.timedelta(days=30)


class Settings(BaseSettings):
    api_path: str = "/api/v1"
    activation_email_code_life_sec: int = 120
    email_connection_config: ConnectionConfig = email_connection_config
    auth_jwt: AuthJWT = AuthJWT()



settings = Settings()
