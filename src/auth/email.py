from random import randint
from fastapi_mail import MessageSchema, FastMail
from src.config import settings
from src.redis import set_value


class Email:
    @staticmethod
    async def send_activation_code(email_to: str):
        random_code = randint(100000, 999999)
        await set_value(key=email_to, value=random_code, ex_time=settings.ACTIVATION_EMAIL_CODE_LIFE_SEC)

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

        fm = FastMail(settings.EMAIL_CONNECTION_CONFIG)

        await fm.send_message(message)


