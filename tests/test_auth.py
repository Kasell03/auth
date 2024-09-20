from datetime import datetime, UTC

import pytest
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from httpx import AsyncClient

from conftest import client, async_session_maker
from src.auth.router import cache_redis, refresh_access_token
from src.config import settings
from src.auth.models import UserModel
from src.auth.schemas import UserWithPasswordSchema, UserJWTSchema, UserActivateSchema, RegisterSchema, LoginSchema, RoleEnum
from src.auth.router import AUTH_ROUT_PREFIX, AuthEndpoint


AUTH_BASE_PATH = f"{settings.api_path}{AUTH_ROUT_PREFIX}"

default_user = UserWithPasswordSchema(
    id=1,
    email="kasell92551@gmail.com",
    username="admin1",
    role=RoleEnum.USER.value,
    updated_at=datetime.now(UTC),
    created_at=datetime.now(UTC),
    password="password",
    is_confirmed=False,
)

secondary_user = UserWithPasswordSchema(
    id=2,
    email="admin2admin2@gmail.com",
    username="admin2",
    role=RoleEnum.USER.value,
    updated_at=datetime.now(UTC),
    created_at=datetime.now(UTC),
    password="password",
    is_confirmed=True,
)


@pytest.fixture
async def db_session():
    async with async_session_maker() as session:
        yield session


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
    async def register_user(ac: AsyncClient, user_data: RegisterSchema):
        return await ac.post(f"{AUTH_BASE_PATH}{AuthEndpoint.REGISTER.value}", json={
            "email": user_data.email,
            "username": user_data.username,
            "password": str(user_data.password)
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

    @staticmethod
    async def get_access_token(user_data: LoginSchema, ac: AsyncClient) -> str:
        response_login = await ApiMethods.login_user(user_data.username, user_data.password, ac)
        access_token = response_login.json()["access_token"]

        return access_token

    @staticmethod
    async def register_confirmed_user(ac: AsyncClient, db_session: AsyncSession, user_data: RegisterSchema, role: RoleEnum):
        await ApiMethods.register_user(ac, RegisterSchema(
            username=user_data.username,
            email=user_data.email,
            password=str(user_data.password),
        ))

        await db_session.execute(
            update(UserModel).filter_by(username=user_data.username).values(role=role, is_confirmed=True))
        await db_session.commit()


class TestRegistration:
    async def test_register_new_user(self, ac: AsyncClient, db_session: AsyncSession):
        response = await ApiMethods.register_default_user(ac)

        user_instance = await db_session.execute(
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





class TestUserMethods:
    async def test_create_secondary_user(self, ac: AsyncClient, db_session: AsyncSession):
        await ApiMethods.register_confirmed_user(ac, db_session, RegisterSchema(
            username=secondary_user.username,
            email=secondary_user.email,
            password=str(secondary_user.password),
        ), role=RoleEnum.ADMIN.value)


    @pytest.mark.parametrize(
        "username, password, expect_code, expect_json",
        [
            (default_user.username, str(default_user.password), 403, {'detail': 'Forbidden'}),
            (secondary_user.username, str(secondary_user.password), 200,
             {'id': 1, 'email': 'kasell92551@gmail.com', 'username': 'admin1', 'role': 'USER'}),
        ]
    )
    async def test_user_get_by_id(self, ac: AsyncClient, username, password, expect_code, expect_json):
        access_token = await ApiMethods.get_access_token(LoginSchema(username=username, password=password), ac=ac)
        assert isinstance(access_token, str)

        response_get_user = await ac.get(f"{AUTH_BASE_PATH}{AuthEndpoint.USER.value}/{default_user.id}", headers={
            "Authorization": f"Bearer {access_token}"
        })

        assert response_get_user.status_code == expect_code
        assert response_get_user.json() == expect_json



    @pytest.mark.parametrize(
        "username, password, expect_code, expect_json, req_json",
        [
            (default_user.username, str(default_user.password), 403, {'detail': 'Forbidden'}, {}),
            (secondary_user.username, str(secondary_user.password), 200, {'msg': 'User has been updated'},
                {"id": 3, "username": "admin3", "password": "None", "email": "admin3@gmail.com", "role": RoleEnum.USER.value}),
            (secondary_user.username, str(secondary_user.password), 409, {"detail": {"msg": "This username already in use"}},
                {"id": 3, "username": default_user.username, "password": "None", "email": "admin3@gmail.com", "role": RoleEnum.USER.value}),
            (secondary_user.username, str(secondary_user.password), 409, {"detail": {"msg": "This email already in use"}},
                {"id": 3, "username": "admin3", "password": "None", "email": default_user.email, "role": RoleEnum.USER.value}),
        ]
    )
    async def test_user_update(self, ac: AsyncClient, db_session: AsyncSession, username, password, expect_code, expect_json, req_json):
        await ApiMethods.register_confirmed_user(ac, db_session, RegisterSchema(username="admin3", email="admin3@gmail.com", password="password"), role=RoleEnum.ADMIN.value)
        access_token = await ApiMethods.get_access_token(LoginSchema(username=username, password=password), ac=ac)
        assert isinstance(access_token, str)

        res_update_user = await ac.put(f"{AUTH_BASE_PATH}{AuthEndpoint.USER.value}", headers={
            "Authorization": f"Bearer {access_token}"
        }, json=req_json)

        assert res_update_user.status_code == expect_code
        assert res_update_user.json() == expect_json


    @pytest.mark.parametrize(
        "req_json",
        [
            ({"id": 3, "username": "admin3", "password": "None", "email": "admin3@gmail.com", "role": RoleEnum.USER.value}),
            ({"id": 3, "username": "admin4", "password": "someNewPassword", "email": "admin4@gmail.com", "role": RoleEnum.ADMIN.value}),
        ]
    )
    async def test_login_updated_user(self, ac: AsyncClient, db_session: AsyncSession, req_json):
        access_token = await ApiMethods.get_access_token(LoginSchema(username=secondary_user.username, password=str(secondary_user.password)), ac=ac)
        assert isinstance(access_token, str)

        user_password = "password"
        if req_json["password"] != "None":
            user_password = req_json["password"]

        await ac.put(f"{AUTH_BASE_PATH}{AuthEndpoint.USER.value}", headers={
            "Authorization": f"Bearer {access_token}"
        }, json=req_json)

        res_login = await ApiMethods.login_user(req_json["username"], user_password, ac)

        assert res_login.status_code == 200
        assert res_login.json()['token_type'] == "bearer"

        updated_user_instance = await db_session.execute(select(UserModel).filter_by(id=req_json["id"]))
        updated_user = UserWithPasswordSchema.model_validate(updated_user_instance.scalars().one())

        assert req_json["username"] == updated_user.username
        assert req_json["email"] == updated_user.email
        assert req_json["role"] == updated_user.role


    async def test_create_new_users(self, ac: AsyncClient, db_session: AsyncSession):
        for i in range(30):
            await ApiMethods.register_user(ac, RegisterSchema(
                email=f"testEmail{i}@gmail.com",
                username=f"testUsername{i}",
                password=f"password"
            ))

    @pytest.mark.parametrize(
        "user_cred, expect_code, offset, expect_first_id, expect_last_id",
        [
            (LoginSchema(username=default_user.username, password=str(default_user.password)), 403, 1, None, None),
            (LoginSchema(username=secondary_user.username, password=str(secondary_user.password)), 200, 1, 1, 10),
            (LoginSchema(username=secondary_user.username, password=str(secondary_user.password)), 200, 2, 11, 20),
            (LoginSchema(username=secondary_user.username, password=str(secondary_user.password)), 200, 3, 21, 30),
        ]
    )
    async def test_user_get_users(self, ac: AsyncClient, user_cred, expect_code, offset, expect_first_id, expect_last_id):
        access_token = await ApiMethods.get_access_token(user_cred, ac=ac)
        assert isinstance(access_token, str)

        response = await ac.get(f"{AUTH_BASE_PATH}{AuthEndpoint.USER.value}?offset={offset}", headers={
            "Authorization": f"Bearer {access_token}"
        })

        assert response.status_code == expect_code
        res_json = response.json()

        if expect_first_id is not None:
            assert res_json[0]["id"] == expect_first_id
            assert res_json[len(res_json) - 1]["id"] == expect_last_id


    @pytest.mark.parametrize(
        "user_cred, expect_code, instance_amount",
        [
            (LoginSchema(username=default_user.username, password=str(default_user.password)), 403, 1),
            (LoginSchema(username=secondary_user.username, password=str(secondary_user.password)), 200, 0),
        ]
    )
    async def test_user_delete(self, ac: AsyncClient, db_session: AsyncSession, user_cred, expect_code, instance_amount):
        access_token = await ApiMethods.get_access_token(user_cred, ac=ac)
        assert isinstance(access_token, str)

        del_user_id = 3

        res_del_user = await ac.delete(f"{AUTH_BASE_PATH}{AuthEndpoint.USER.value}/{del_user_id}", headers={
            "Authorization": f"Bearer {access_token}"
        })

        assert res_del_user.status_code == expect_code

        deleted_user_instance = await db_session.execute(select(UserModel).filter_by(id=del_user_id))
        assert len(deleted_user_instance.scalars().all()) == instance_amount


    async def test_user_get_me(self, ac: AsyncClient):
        access_token = await ApiMethods.get_access_token(LoginSchema(
            username=default_user.username,
            password=str(default_user.password)
        ), ac=ac)
        assert isinstance(access_token, str)

        res_get_me = await ac.get(f"{AUTH_BASE_PATH}{AuthEndpoint.ME.value}", headers={
            "Authorization": f"Bearer {access_token}"
        })

        res_json = res_get_me.json()
        assert res_get_me.status_code == 200
        assert res_json['id'] == default_user.id
        assert res_json['username'] == default_user.username
        assert res_json['email'] == default_user.email


    @pytest.mark.parametrize(
        "old_username, old_email, old_password, new_username, new_email, new_password, expect_code",
        [
            (default_user.username, default_user.email, default_user.password, secondary_user.username, default_user.email, "None", 409),
            (default_user.username, default_user.email, default_user.password, default_user.username, secondary_user.email, "None", 409),
            (default_user.username, default_user.email, default_user.password, "newUsername", "newEmail@gmail.com", "None", 200),
            ("newUsername", "newEmail@gmail.com", default_user.password, "newUsername", "newEmail@gmail.com", "newPassword", 200),
            ("newUsername", "newEmail@gmail.com", "newPassword", "newUsername", "newEmail@gmail.com", "None", 200),
        ]
    )
    async def test_user_update_me(self, ac: AsyncClient, old_username, old_email, old_password, new_username, new_email, new_password, expect_code):
        access_token = await ApiMethods.get_access_token(LoginSchema(
            username=old_username,
            password=str(old_password)
        ), ac=ac)
        assert isinstance(access_token, str)

        res_update_me = await ac.put(f"{AUTH_BASE_PATH}{AuthEndpoint.ME.value}",
                                     headers={
                                         "Authorization": f"Bearer {access_token}"
                                     },
                                     json={
                                        "id": 1,
                                        "email": new_email,
                                        "username": new_username,
                                        "password": new_password
                                     })

        assert res_update_me.status_code == expect_code

        if expect_code == 200:
            user_password = old_password
            if new_password != "None":
                user_password = new_password

            res_login = await ApiMethods.login_user(new_username, str(user_password), ac)
            assert res_login.status_code == 200

            res_get_me = await ac.get(f"{AUTH_BASE_PATH}{AuthEndpoint.ME.value}", headers={
                "Authorization": f"Bearer {access_token}"
            })
            assert res_get_me.json()['email'] == new_email







