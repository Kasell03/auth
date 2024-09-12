import datetime
from typing import Annotated

from sqlalchemy import MetaData, Column, Table, String, TIMESTAMP, ForeignKey, JSON, text, Enum, LargeBinary, Boolean
from sqlalchemy.orm import Mapped, mapped_column

from src.database import Base, str_32, str_64, str_128, str_256, str_512
from src.auth.schemas import RoleEnum


intpk = Annotated[int, mapped_column(primary_key=True)]
created_at = Annotated[datetime.datetime, mapped_column(server_default=text("TIMEZONE('utc', now())"))]
updated_at = Annotated[datetime.datetime, mapped_column(
    server_default=text("TIMEZONE('utc', now())"),
    onupdate=lambda: datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
)]


class UserModel(Base):
    __tablename__ = "User"

    id: Mapped[intpk]
    email: Mapped[str_128] = mapped_column(String, unique=True, nullable=False)
    username: Mapped[str_64] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    role: Mapped[RoleEnum] = mapped_column(Enum(RoleEnum), default=RoleEnum.USER, nullable=False)
    is_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[created_at]
    updated_at: Mapped[updated_at]

