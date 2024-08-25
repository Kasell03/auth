import datetime
from enum import Enum
from pydantic import BaseModel, field_validator, model_validator, Field, conint


class RoleEnum(Enum):
    SUPERUSER = "SUPERUSER"
    ADMIN = "ADMIN"
    USER = "USER"


class FormAttribute(BaseModel):
    class Config:
        from_attributes = True


class UserJWT(FormAttribute):
    id: int
    email: str
    username: str
    role: str


class UserNoPasswordSchema(UserJWT):
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


class UserDataJWT(FormAttribute):
    id: int
    username: str
    email: str
    role: RoleEnum

class UserActivateSchema(LoginSchema):
    code: conint(gt=99999, lt=1000000)