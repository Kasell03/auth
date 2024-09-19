import datetime
from enum import Enum
from typing import Annotated, Optional

from pydantic import BaseModel, ConfigDict, Field, conint


class RoleEnum(Enum):
    USER = "USER"
    ADMIN = "ADMIN"
    SUPERUSER = "SUPERUSER"


class FormAttribute(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)


class UserBaseSchema(FormAttribute):
    id: int
    email: str = Field(min_length=8, max_length=64)
    username: str = Field(min_length=4, max_length=16)

class UserJWTSchema(UserBaseSchema):
    role: RoleEnum


class UserUpdateSchema(UserJWTSchema):
    password: str


class UserMeUpdateSchema(UserBaseSchema):
    password: str


class UserNoPasswordSchema(UserJWTSchema):
    updated_at: datetime.datetime
    created_at: datetime.datetime


class UserWithConfirmSchema(UserNoPasswordSchema):
    is_confirmed: bool


class UserWithPasswordSchema(UserWithConfirmSchema):
    password: bytes


class RegisterSchema(FormAttribute):
    email: str = Field(min_length=8, max_length=64)
    username: str = Field(min_length=4, max_length=16)
    password: str = Field(min_length=8, max_length=32)


class LoginSchema(FormAttribute):
    username: str = Field(min_length=4, max_length=16)
    password: str = Field(min_length=8, max_length=32)


class Token(FormAttribute):
    token_type: str
    access_token: str
    refresh_token: str | None = None


class UserActivateSchema(LoginSchema):
    code: conint(gt=99999, lt=1000000)