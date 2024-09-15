import asyncio
from random import randint
from typing import Coroutine, Callable, Any, Union

from fastapi import HTTPException, status
from fastapi_mail import MessageSchema, FastMail
from src.config import settings


class Email:
    @staticmethod
    async def send_activation_code(email_to: str,
                                   get_redis_value: Callable[[str], Coroutine[Any, Any, Union[str, int, None]]],
                                   set_redis_value: Callable[[str, Union[str, int], int], Coroutine[Any, Any, None]],
                                   ):
        is_code_set = await get_redis_value(email_to)
        if is_code_set is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"msg": "Code hasn't expired yet"},
            )

        random_code = randint(100000, 999999)
        await set_redis_value(email_to, random_code, settings.activation_email_code_life_sec)

        body = f"""
            Activation code: {random_code}
        """

        message = MessageSchema(
            subject="Account activation",
            recipients=[email_to],
            body=body,
            charset="utf-8",
            subtype='html',
        )

        fm = FastMail(settings.email_connection_config)

        await fm.send_message(message)

