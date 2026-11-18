import time
from typing import Any
from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import ORJSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class ApiError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        data: Any = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.data = data


def ok_response(
    data: Any = None,
    message: str = "OK",
    code: str = "OK",
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> ORJSONResponse:
    return ORJSONResponse(
        status_code=status_code,
        headers=headers,
        content={
            "ok": True,
            "code": code,
            "message": message,
            "data": data if data is not None else {},
            "server_time": int(time.time()),
        },
    )


def err_response(
    status_code: int,
    code: str,
    message: str,
    data: Any = None,
) -> ORJSONResponse:
    return ORJSONResponse(
        status_code=status_code,
        content={
            "ok": False,
            "code": code,
            "message": message,
            "data": data if data is not None else {},
            "server_time": int(time.time()),
        },
    )


async def api_error_handler(_: Request, exc: ApiError) -> ORJSONResponse:
    return err_response(exc.status_code, exc.code, exc.message, exc.data)


async def http_error_handler(_: Request, exc: StarletteHTTPException) -> ORJSONResponse:
    return err_response(exc.status_code, f"HTTP_{exc.status_code}", str(exc.detail))


async def validation_error_handler(_: Request, exc: RequestValidationError) -> ORJSONResponse:
    return err_response(
        422,
        "VALIDATION_ERROR",
        "Некорректный формат входных данных",
        {"errors": exc.errors()},
    )
