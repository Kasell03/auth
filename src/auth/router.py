import enum
from typing import NoReturn
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
import os
import sys

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from .email import Email
from src.auth import schemas
from src.auth import security
from .dependencies import SessionDep, TokenDep, AuthDep
from .crud import UserCRUD
from src.cache_redis import CacheRedis


user_router = APIRouter()
cache_redis = CacheRedis()

AUTH_ROUT_PREFIX = "/auth"
class AuthEndpoint(enum.Enum):
    REGISTER="/register"
    LOGIN="/login"
    AUTHORIZE="/authorize"
    GET_CODE="/get-code"
    ACTIVATE_ACCOUNT="/activate-account"
    USER="/user"
    SELF="/self"


async def check_user(request_form: AuthDep, session: SessionDep) -> list[schemas.UserSchema] | NoReturn:
    not_valid_credentials = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"msg": "Incorrect username or password"},
        headers={"WWW-Authenticate": "Bearer"},
    )

    users = await UserCRUD.get_user_by_field(session, schemas.UserSchema, username=request_form.username)

    if len(users) == 0:
        raise not_valid_credentials
    else:
        selected_user = users[0]

        is_pass_valid = security.validate_password(
            password=request_form.password,
            hashed_password=selected_user.password)

        if not is_pass_valid:
            raise not_valid_credentials

    return users


@user_router.post(AuthEndpoint.REGISTER.value)
async def register_user(request: schemas.RegisterSchema, session: SessionDep):
    user_by_email = await UserCRUD.get_user_by_field(session, schemas.UserNoPasswordSchema, email=request.email)
    user_by_username = await UserCRUD.get_user_by_field(session, schemas.UserNoPasswordSchema, username=request.username)

    if len(user_by_email) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"msg": "This email already in use"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    if len(user_by_username) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"msg": "This username already in use"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await UserCRUD.insert_user(
        session=session,
        user_data=schemas.RegisterSchema(
            username=request.username,
            email=request.email,
            password=request.password
        ))

    jwt_token = security.encode_jwt(user_data=result)

    # return schemas.Token(access_token=jwt_token, token_type="bearer")
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"msg": "Account has been created"}
    )


@user_router.post(AuthEndpoint.LOGIN.value)
async def login_user(request_form: AuthDep, session: SessionDep):
    users = await check_user(request_form, session)

    if users[0].is_confirmed is False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"msg": "Account has not been activated"},
        )

    jwt_token = security.encode_jwt(user_data=users[0])

    return schemas.Token(access_token=jwt_token, token_type="bearer")


@user_router.post(AuthEndpoint.AUTHORIZE.value)
async def validate_token(token: TokenDep, session: SessionDep):
    not_valid_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "msg": "Invalid token"
            }
        )

    decoded = security.decode_jwt(token=token)

    if decoded:
        current_user = await UserCRUD.get_user_by_field(session, schemas.UserJWT, id=decoded.id)

        if current_user[0] == decoded:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "msg": "Token is valid"
                }
            )
        else:
            raise not_valid_exception
    else:
        raise not_valid_exception


@user_router.post(AuthEndpoint.GET_CODE.value)
async def send_activation_code(request_form: AuthDep, session: SessionDep):
    users = await check_user(request_form, session)

    if users[0].is_confirmed is True:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"msg": "Account is active"},
        )

    user_email = users[0].email
    user_email = "kasell92551@gmail.com"
    await Email.send_activation_code(user_email, cache_redis.get_value, cache_redis.set_value)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"msg": "Code has been sent"}
    )


@user_router.post(AuthEndpoint.ACTIVATE_ACCOUNT.value)
async def activate_account(request: schemas.UserActivateSchema, session: SessionDep):
    users = await check_user(request, session)

    if users[0].is_confirmed is True:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"msg": "Account is active"},
        )

    user_email = users[0].email
    user_email = "kasell92551@gmail.com"

    entered_code = request.code
    given_code = await cache_redis.get_value(user_email)
    if given_code is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"msg": "Code has been expired"},
        )

    if int(entered_code) != int(given_code):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"msg": "Incorrect code"},
        )

    user_jwt_schema = await UserCRUD.activate_user(session, users[0])
    jwt_token = security.encode_jwt(user_data=user_jwt_schema)
    await cache_redis.del_value(user_email)

    return schemas.Token(access_token=jwt_token, token_type="bearer")


@user_router.get(AuthEndpoint.USER.value + "/{user_id}")
async def user_get(user_id: int, session: SessionDep, role: security.UserRoleDep):
    return await UserCRUD.get_user_by_field(session, schemas.UserJWT, id=user_id)


@user_router.put(AuthEndpoint.USER.value)
async def user_update(request: schemas.UserUpdate, session: SessionDep, role: security.UserRoleDep):
    # Либо создать новую схему, которую будет принимать запрос
    # Либо выбрать из существующих схем
    pass


@user_router.delete(AuthEndpoint.USER.value + "/{user_id}")
async def user_delete(user_id: int, session: SessionDep, role: security.UserRoleDep):
    await UserCRUD.delete_user(session=session, user_id=user_id)

    return JSONResponse(
        status_code=200,
        content={"msg": "User has been deleted"}
    )


# @user_router.get('Получить всех пользователей(с пагинацией)')
# @user_router.put('Обновить конкретного пользователя)')
# @user_router.delete('Удалить конкретного пользователя)')
# @user_router.get('Получить себя')
# @user_router.put('Обновить себя')
