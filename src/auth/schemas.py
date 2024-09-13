import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field, conint


class RoleEnum(Enum):
    USER = "USER"
    ADMIN = "ADMIN"
    SUPERUSER = "SUPERUSER"


class FormAttribute(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)


class UserJWTSchema(FormAttribute):
    id: int
    email: str = Field(min_length=8, max_length=64)
    username: str = Field(min_length=4, max_length=16)
    role: RoleEnum


class UserUpdateSchema(UserJWTSchema):
    password: str


class UserNoPasswordSchema(UserJWTSchema):
    updated_at: datetime.datetime
    created_at: datetime.datetime


class UserSchema(UserNoPasswordSchema):
    password: bytes
    is_confirmed: bool


class RegisterSchema(FormAttribute):
    email: str = Field(min_length=8, max_length=64)
    username: str = Field(min_length=4, max_length=16)
    password: str = Field(min_length=8, max_length=32)


class LoginSchema(FormAttribute):
    username: str = Field(min_length=4, max_length=16)
    password: str = Field(min_length=8, max_length=32)


class Token(FormAttribute):
    access_token: str
    token_type: str


class UserActivateSchema(LoginSchema):
    code: conint(gt=99999, lt=1000000)