from random import randint
from typing import Annotated, NoReturn
from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
import os
import sys
from fastapi.security import OAuth2PasswordRequestForm

sys.path.insert(1, os.path.join(sys.path[0], '..'))
from .email import Email
from src.auth import schemas
from src.auth import security
from .dependencies import SessionDep, TokenDep, AuthDep
from .crud import UserCRUD
from src.redis import get_value, set_value, del_value


user_router = APIRouter()


@user_router.get('/user')
async def get_user(session: SessionDep, token: TokenDep):
    # res = await security.verify_jwt(token=token)
    # validate(role=schemas.RoleEnum.ADMIN)
    # return res
    # try:
    # user = await UserCRUD.get_user_by_field(session=session, username="admin")
    # print(user)
    # print('----')
    # for i in user:
    #     print(i)
    # print(type(await get_category("auth")))
    # await set_value( "new_user2", 1114, 60)
    await del_value("new_user2")

    # print(await get_value("kadoskd"))
    # print(redis_app.get('auth'))
    #     # print(AuthHash.decode_jwt(token))
    #     query = select(UserModel)
    #     result = await session.execute(query)
    #     # jwt.exceptions.ExpiredSignatureError # Истекло время
    #     # jwt.exceptions.InvalidSignatureError # Некорректная хэш сума
    #
    #     # В ГИТЕ ПРИМЕР В ФАЙЛЕ deps.py
    #
    #
    #     # users = users_dict_from_ORM(result, schemas.UserSchema)
    #     users = result.scalars().all()
    #
    #     return users
    #     # return result
    # except Exception as ex:
    #     return JSONResponse(status_code=409, content={'err': 'er'})


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


@user_router.post('/register')
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


@user_router.post('/login')
async def login_user(request_form: AuthDep, session: SessionDep):
    users = await check_user(request_form, session)

    if users[0].is_confirmed is False:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"msg": "Account has not been activated"},
        )

    jwt_token = security.encode_jwt(user_data=users[0])

    return schemas.Token(access_token=jwt_token, token_type="bearer")


@user_router.post('/authorize')
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


@user_router.post('/get-code')
async def send_activation_code(request_form: AuthDep, session: SessionDep):
    users = await check_user(request_form, session)

    if users[0].is_confirmed is True:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"msg": "Account is active"},
        )

    user_email = users[0].email
    user_email = "kasell92551@gmail.com"
    await Email.send_activation_code(user_email)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"msg": "Code has been send"}
    )


@user_router.post('/activate-account')
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
    given_code = await get_value(user_email)
    if not given_code:
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

    return schemas.Token(access_token=jwt_token, token_type="bearer")


# @user_router.get('Получить всех пользователей(с пагинацией)')
# @user_router.get('Получить конкретного пользователя)')
# @user_router.put('Обновить конкретного пользователя)')
# @user_router.delete('Удалить конкретного пользователя)')
# @user_router.get('Получить себя')
# @user_router.put('Обновить себя')
