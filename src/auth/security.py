import datetime
import os
import sys
from typing import Type, Union, Literal, Annotated

import bcrypt
import jwt
from jwt.exceptions import InvalidSignatureError, ExpiredSignatureError, DecodeError
from fastapi import HTTPException, status, Depends

sys.path.insert(1, os.path.join(sys.path[0], '..'))

from src.config import settings
from src.auth import schemas
from src.auth.dependencies import TokenDep


def encode_jwt(user_data: schemas.UserJWT) -> str:
    expire = datetime.datetime.now(datetime.UTC) + settings.JWT_TOKEN_LIFE_TIME
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


def check_role(role: Literal["USER", "ADMIN"]):
    def __check_role(token: TokenDep):
        invalid_token_exception = HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"msg": "Invalid token"}
        )

        try:
            decoded_token = decode_jwt(token)
            if decoded_token is False:
                raise invalid_token_exception

            if role != decoded_token.role:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                )

        except DecodeError:
            raise invalid_token_exception

    return __check_role

UserRoleDep = Annotated[None, Depends(check_role("USER"))]
AdminRoleDep = Annotated[None, Depends(check_role("ADMIN"))]