from typing import Type, NoReturn

from fastapi import HTTPException, status
from sqlalchemy import text, select, insert, update, Result, delete, or_, and_
from starlette.responses import JSONResponse
from starlette.status import HTTP_404_NOT_FOUND, HTTP_409_CONFLICT

from src.auth.models import UserModel
from src.auth import schemas
from .dependencies import SessionDep, TokenDep
from . import security


async def is_email_or_username_inuse(user_id: int, username: str, email: str, session: SessionDep) -> False | NoReturn:
    search_for_username_email = await session.execute(
        select(UserModel)
        .where(
            or_(
                UserModel.username == username,
                UserModel.email == email
            ),
            and_(
                UserModel.id != user_id
            )
        )
    )

    search_result_list = list(
        map(lambda r: schemas.UserUpdateSchema.model_validate(r), search_for_username_email.scalars().all()))
    if len(search_result_list) > 0:
        for sr in search_result_list:
            if sr.username == username:
                raise HTTPException(
                    status_code=HTTP_409_CONFLICT,
                    detail={"msg": "This username already in use"}
                )
            elif sr.email == sr.email:
                raise HTTPException(
                    status_code=HTTP_409_CONFLICT,
                    detail={"msg": "This email already in use"}
                )

    return False


class UserCRUD:
    @staticmethod
    async def insert_user(
            session: SessionDep,
            user_data: schemas.RegisterSchema
    ) -> schemas.UserNoPasswordSchema:
        try:
            hashed_password = security.hash_password(user_data.password)

            query = (
                insert(UserModel)
                .values(
                    username=user_data.username,
                    email=user_data.email,
                    password=hashed_password,
                )
                .returning(
                    UserModel.id,
                    UserModel.username,
                    UserModel.email,
                    UserModel.role,
                    UserModel.created_at,
                    UserModel.updated_at,

                )
            )

            result = await session.execute(query)
            result = result.fetchone()

            await session.commit()

            return schemas.UserNoPasswordSchema.model_validate(result)
        except Exception as ex:
            print(ex)
            print("crud.py/insert_user()")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @staticmethod
    async def get_user_by_field(
            session: SessionDep,
            schema: Type[schemas.UserNoPasswordSchema] | Type[schemas.UserSchema] | Type[schemas.UserJWTSchema] | Type[schemas.UserUpdateSchema],
            **kwargs) -> list[schemas.UserNoPasswordSchema] | list[schemas.UserSchema] | list[schemas.UserJWTSchema] | list[schemas.UserUpdateSchema]:
        try:
            result = await session.execute(
                select(UserModel)
                .filter_by(**kwargs)
            )

            return list(map(lambda r: schema.model_validate(r), result.scalars().all()))
        except Exception as ex:
            print("crud.py/get_user_by_field()")
            print(ex)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @staticmethod
    async def activate_user(session: SessionDep, schema: schemas.UserSchema) -> schemas.UserJWTSchema:
        try:
            result = await session.execute(
                update(UserModel)
                .values(is_confirmed=True)
                .filter_by(id=schema.id)
            )

            await session.commit()
            affected_rows = result.rowcount

            if affected_rows > 0:
                return schemas.UserJWTSchema.model_validate(schema)
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        except Exception as ex:
            print("crud.py/activate_user()")
            print(ex)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @staticmethod
    async def update_user(session: SessionDep, user_data: schemas.UserUpdateSchema):
        user_instance = await UserCRUD.get_user_by_field(session, schemas.UserUpdateSchema, id=user_data.id)
        if len(user_instance) == 0:
            raise HTTPException(
                status_code=HTTP_404_NOT_FOUND,
                detail={"msg": "User has not been found"}
            )

        user_password = str(user_instance[0].password).encode()
        await is_email_or_username_inuse(user_data.id, user_data.username, user_data.email, session)
        if user_data.password != "None":
            user_password = security.hash_password(user_data.password)

        await session.execute(
            update(UserModel)
            .values(
                username=user_data.username,
                email=user_data.email,
                role=user_data.role,
                password=user_password,
            )
            .filter_by(id=user_data.id)
        )

        await session.commit()

    @staticmethod
    async def delete_user(session: SessionDep, user_id: int):
        result = await session.execute(delete(UserModel).filter_by(id=user_id))
        if result.rowcount > 0:
            await session.commit()
            return
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"msg": "User has not been found"}
            )


