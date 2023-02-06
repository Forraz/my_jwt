import asyncio
import os
import time
from base64 import b64encode, b64decode

import aiocron

from jwt.models import TokensModel

os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"


def encode(data):
    """Кодирует строку в байт64 строку"""

    return b64encode(str(data).encode())


def decode(data) -> dict:
    """Декодирует байт64-строку в словарь"""

    data = b64decode(data).decode()

    return eval(data)


def payload_decode(token: str | dict) -> dict:
    """Извлекает и декодирует payload из токена"""

    if type(token) == str:
        return decode(token.split('.')[1].encode())
    elif type(token) == dict:
        return token

    raise TypeError