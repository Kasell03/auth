from datetime import datetime, UTC

import pytest
from sqlalchemy import insert, select

from src.auth.router import cache_redis, refresh_access_token
from src.config import settings
from httpx import AsyncClient

from conftest import client, async_session_maker
from src.auth.models import UserModel
from src.auth.schemas import UserWithPasswordSchema, UserJWTSchema, UserActivateSchema
from src.auth.router import AUTH_ROUT_PREFIX, AuthEndpoint


AUTH_BASE_PATH = f"{settings.api_path}{AUTH_ROUT_PREFIX}"

default_user = UserWithPasswordSchema(
    id=1,
    email="kasell92551@gmail.com",
    username="admin1",
    role="USER",
    updated_at=datetime.now(UTC),
    created_at=datetime.now(UTC),
    password="password",
    is_confirmed=False,
)

@pytest.fixture
async def redis_delete_default_email():
    await cache_redis.del_value(default_user.email)


class ApiMethods:
    @staticmethod
    async def register_default_user(ac: AsyncClient):
        return await ac.post(f"{AUTH_BASE_PATH}{AuthEndpoint.REGISTER.value}", json={
            "email": default_user.email,
            "username": default_user.username,
            "password": str(default_user.password)
        })

    @staticmethod
    async def login_user(username: str, password: str, ac: AsyncClient):
        return await ac.post(f"{AUTH_BASE_PATH}{AuthEndpoint.LOGIN.value}", data={
            "username": username,
            "password": password
        })

    @staticmethod
    async def get_activation_code(username: str, password: str, ac: AsyncClient):
        return await ac.post(f"{AUTH_BASE_PATH}{AuthEndpoint.GET_CODE.value}", data={
            "username": username,
            "password": password
        })

    @staticmethod
    async def send_activation_code(user_data: UserActivateSchema, ac: AsyncClient):
        return await ac.post(f"{AUTH_BASE_PATH}{AuthEndpoint.ACTIVATE_ACCOUNT.value}", json={
            "username": user_data.username,
            "password": user_data.password,
            "code": user_data.code
        })


class TestRegistration:
    async def test_register_new_user(self, ac: AsyncClient):
        response = await ApiMethods.register_default_user(ac)

        async with async_session_maker() as session:
            user_instance = await session.execute(
                select(UserModel)
                .filter_by(
                    email=default_user.email
                )
            )

            added_user = UserWithPasswordSchema.model_validate(user_instance.scalars().one())

        assert added_user.id == default_user.id
        assert added_user.username == default_user.username
        assert added_user.email == default_user.email
        assert added_user.role == default_user.role
        assert added_user.is_confirmed == default_user.is_confirmed
        assert response.status_code == 201

    async def test_register_existing_user(self, ac: AsyncClient):
        response = await ApiMethods.register_default_user(ac)

        assert response.status_code == 409


class TestLogin:
    async def test_login_unactivated_user(self, ac: AsyncClient):
        response = await ApiMethods.login_user(default_user.username, str(default_user.password), ac)
        assert response.status_code == 403
        assert response.json() == {"detail": {"msg": 'Account has not been activated'}}

    @pytest.mark.usefixtures("redis_delete_default_email")
    async def test_get_activation_code(self, ac: AsyncClient):
        response = await ApiMethods.get_activation_code(
            username=default_user.username,
            password=str(default_user.password),
            ac=ac,
        )

        assert response.status_code == 200
        assert response.json() == {'msg': 'Code has been sent'}

    async def test_activate_user_incorrect_code(self, ac: AsyncClient):
        activation_code = await cache_redis.get_value(default_user.email)
        assert activation_code is not None
        incorrect_code = 100000
        if activation_code == incorrect_code:
            incorrect_code = 100001

        result = await ApiMethods.send_activation_code(
            user_data=UserActivateSchema(
                username=default_user.username,
                password=str(default_user.password),
                code=incorrect_code
            ),
            ac=ac,
        )

        assert result.status_code == 409
        assert result.json() == {"detail": {"msg": "Incorrect code"}}

    @pytest.mark.usefixtures("redis_delete_default_email")
    async def test_activation_code_expired(self, ac: AsyncClient):
        result = await ApiMethods.send_activation_code(
            user_data=UserActivateSchema(
                username=default_user.username,
                password=str(default_user.password),
                code=100000
            ),
            ac=ac,
        )

        assert result.status_code == 404
        assert result.json() == {"detail": {"msg": "Code has been expired"}}

    @pytest.mark.usefixtures("redis_delete_default_email")
    async def test_activate_user(self, ac: AsyncClient):

        user_data = UserActivateSchema(
            username=default_user.username,
            password=str(default_user.password),
            code=100000
        )
        await cache_redis.set_value(key=default_user.email, value=user_data.code, ex_time_sec=60)
        given_code = await cache_redis.get_value(key=default_user.email)

        assert int(given_code) == user_data.code

        activation_response = await ApiMethods.send_activation_code(user_data=user_data, ac=ac)
        assert activation_response.status_code == 200
        assert activation_response.json()["token_type"] == "bearer"
        assert isinstance(activation_response.json()["access_token"], str)
        assert isinstance(activation_response.json()["refresh_token"], str)

        user_is_activated_response = await ApiMethods.send_activation_code(user_data=user_data, ac=ac)
        assert user_is_activated_response.status_code == 409
        assert user_is_activated_response.json() == {"detail": {"msg": "Account is active"}}

    async def test_refresh_jwt(self, ac: AsyncClient):
        login_res = await ApiMethods.login_user(default_user.username, str(default_user.password), ac)
        res_refresh_token = login_res.json()['refresh_token']
        res_access_token = login_res.json()['access_token']

        assert login_res.status_code == 200

        refresh_fail_res = await ac.post(f"{AUTH_BASE_PATH}{AuthEndpoint.REFRESH_ACCESS.value}", headers={
            "Authorization": f"Bearer {res_access_token}"
        })

        assert refresh_fail_res.status_code == 400
        assert refresh_fail_res.json() == {"detail": {"msg": f"expected type 'refresh' got 'access' instead"}}

        refresh_success_res = await ac.post(f"{AUTH_BASE_PATH}{AuthEndpoint.REFRESH_ACCESS.value}", headers={
            "Authorization": f"Bearer {res_refresh_token}"
        })

        assert refresh_success_res.status_code == 200
        assert isinstance(refresh_success_res.json()["access_token"], str)
