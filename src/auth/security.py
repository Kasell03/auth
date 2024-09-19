import datetime
import os
import sys
from typing import Type, Union, Literal, Annotated, NoReturn

import bcrypt
import jwt
from jwt.exceptions import InvalidSignatureError, ExpiredSignatureError, DecodeError, InvalidAlgorithmError
from fastapi import HTTPException, status, Depends
from starlette.status import HTTP_400_BAD_REQUEST

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from src.config import settings
from src.auth import schemas
from src.auth.dependencies import TokenDep


ACCESS_JWT_TYPE = "access"
REFRESH_JWT_TYPE = "refresh"
TOKEN_TYPE_FIELD = "type"
TOKEN_TYPE_BEARER = "bearer"


def _create_access_jwt(user_data: schemas.UserJWTSchema) -> str:
    jwt_payload = {
        TOKEN_TYPE_FIELD: ACCESS_JWT_TYPE,
        "exp": datetime.datetime.now(datetime.UTC) + settings.auth_jwt.access_token_life_time,
        "id": user_data.id,
        "username": user_data.username,
        "email": user_data.email,
        "role": user_data.role,
    }
    return jwt.encode(
        payload=jwt_payload,
        key=settings.auth_jwt.private_key_path.read_text(),
        algorithm=settings.auth_jwt.algorithm
    )


def _create_refresh_jwt(user_data: schemas.UserJWTSchema) -> str:
    jwt_payload = {
        TOKEN_TYPE_FIELD: REFRESH_JWT_TYPE,
        "exp": datetime.datetime.now(datetime.UTC) + settings.auth_jwt.refresh_token_life_time,
        "id": user_data.id,
        "username": user_data.username,
        "email": user_data.email,
        "role": user_data.role,
    }
    return jwt.encode(
        payload=jwt_payload,
        key=settings.auth_jwt.private_key_path.read_text(),
        algorithm=settings.auth_jwt.algorithm
    )


def create_jwt(user_data: schemas.UserJWTSchema) -> schemas.Token:
    return schemas.Token(
        token_type=TOKEN_TYPE_BEARER,
        access_token=_create_access_jwt(user_data),
        refresh_token=_create_refresh_jwt(user_data),
    )

def verify_jwt(any_token: str, expect_token_type: Union[ACCESS_JWT_TYPE, REFRESH_JWT_TYPE]) -> schemas.UserJWTSchema | NoReturn:
   decoded_jwt = _decode_jwt(any_token)

   token_type = decoded_jwt["type"]

   if token_type != expect_token_type:
       raise HTTPException(
           status_code=HTTP_400_BAD_REQUEST,
           detail={"msg": f"expected type {expect_token_type!r} got {token_type!r} instead"}
       )

   return schemas.UserJWTSchema.model_validate(decoded_jwt)


def refresh_access_jwt(refresh_token: TokenDep) -> schemas.Token:
    user_data = verify_jwt(any_token=refresh_token, expect_token_type=REFRESH_JWT_TYPE)
    return schemas.Token(
        token_type=TOKEN_TYPE_BEARER,
        access_token=_create_access_jwt(user_data),
    )


def _decode_jwt(any_token: str) -> dict | NoReturn:
    try:
        decoded = jwt.decode(
            jwt=any_token,
            key=settings.auth_jwt.public_key_path.read_text(),
            algorithms=[settings.auth_jwt.algorithm]
        )

        return decoded

    except (InvalidSignatureError, ExpiredSignatureError, DecodeError, InvalidAlgorithmError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "msg": "Invalid token"
            }
        )


def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)


def validate_password(password: str, hashed_password: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password)


def check_role(role: Literal["USER", "ADMIN"]) -> schemas.UserJWTSchema | NoReturn:
    def __check_role(access_token: TokenDep):
        user_data = verify_jwt(any_token=access_token, expect_token_type=ACCESS_JWT_TYPE)

        if role != user_data.role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
            )

        return user_data

    return __check_role

UserRoleDep = Annotated[None, Depends(check_role("USER"))]
AdminRoleDep = Annotated[None, Depends(check_role("ADMIN"))]
