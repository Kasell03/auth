import datetime
import os
import sys
from typing import Type, Union

import bcrypt
import jwt
from jwt.exceptions import InvalidSignatureError, ExpiredSignatureError
from fastapi import HTTPException, status
from sqlalchemy.ext.baked import Result
from starlette.responses import JSONResponse

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from src.config import settings
from src.auth import schemas


def encode_jwt(user_data: schemas.UserJWT) -> str:
    expire = datetime.datetime.utcnow() + settings.JWT_TOKEN_LIFE_TIME
    payload = {
        "id": user_data.id,
        "username": user_data.username,
        "email": user_data.email,
        "role": user_data.role,
    }
    payload.update({"exp": expire})

    return jwt.encode(payload=payload, key=settings.SECRET, algorithm=settings.ALGORITHM)


def decode_jwt(token: str) -> Union[schemas.UserJWT, False]:
    try:
        decoded = jwt.decode(token, settings.SECRET, algorithms=[settings.ALGORITHM])
        return schemas.UserJWT.model_validate(decoded)

    except (InvalidSignatureError, ExpiredSignatureError):
        return False


def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)


def validate_password(password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password)


def users_dict_from_ORM(orm_result: Result, schema: Type[schemas.UserSchema | schemas.UserNoPasswordSchema]) -> (
        list)[Type[schemas.UserSchema | schemas.UserNoPasswordSchema]]:
    return [schema.from_orm(user) for user in orm_result.scalars().all()]
