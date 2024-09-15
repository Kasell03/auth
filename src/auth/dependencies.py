from typing import Annotated

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from src.database import get_async_session
from src.config import settings


reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl=f"{settings.api_path}/auth/login"
)


SessionDep = Annotated[Session, Depends(get_async_session)]
TokenDep = Annotated[str, Depends(reusable_oauth2)]
AuthDep = Annotated[OAuth2PasswordRequestForm, Depends()]

