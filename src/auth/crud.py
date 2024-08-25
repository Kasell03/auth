from typing import Type

from fastapi import HTTPException, status
from sqlalchemy import text, select, insert, update, Result
from src.auth.models import UserModel
from src.auth import schemas
from .dependencies import SessionDep, TokenDep
from . import security


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
            schema: Type[schemas.UserNoPasswordSchema] | Type[schemas.UserSchema] | Type[schemas.UserJWT],
            **kwargs) -> list[schemas.UserNoPasswordSchema] | list[schemas.UserSchema] | list[schemas.UserJWT]:
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
    async def activate_user(session: SessionDep, user: schemas.UserSchema) -> schemas.UserJWT:
        try:
            result = await session.execute(
                update(UserModel)
                .values(is_confirmed=True)
                .filter_by(id=user.id)
            )

            await session.commit()
            affected_rows = result.rowcount

            if affected_rows > 0:
                return schemas.UserJWT.model_validate(user)
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

