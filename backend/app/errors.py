"""RFC 9457 problem details (docs/05-api-specification.md §1)."""

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

PROBLEM_JSON = "application/problem+json"


class ProblemError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        title: str,
        detail: str | None = None,
        *,
        errors: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(title)
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.errors = errors
        self.headers = headers


def forbidden(detail: str = "You do not have permission for this action.") -> ProblemError:
    return ProblemError(403, "authz.forbidden", "Forbidden", detail)


def not_found(what: str = "Resource") -> ProblemError:
    return ProblemError(404, "resource.not_found", "Not found", f"{what} not found.")


def unauthorized(detail: str = "Authentication required.") -> ProblemError:
    return ProblemError(401, "auth.unauthenticated", "Unauthorized", detail, headers={"WWW-Authenticate": "Bearer"})


def _body(request: Request, status: int, code: str, title: str, detail: str | None) -> dict[str, Any]:
    return {
        "type": f"https://errors.nocsoc.local/{code}",
        "title": title,
        "status": status,
        "detail": detail,
        "instance": request.url.path,
        "code": code,
    }


def install(app: FastAPI) -> None:
    @app.exception_handler(ProblemError)
    async def _problem(request: Request, exc: ProblemError) -> JSONResponse:
        body = _body(request, exc.status, exc.code, exc.title, exc.detail)
        if exc.errors:
            body["errors"] = exc.errors
        return JSONResponse(body, status_code=exc.status, media_type=PROBLEM_JSON, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"loc": list(e.get("loc", [])), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()
        ]
        body = _body(request, 422, "validation.failed", "Validation failed", None)
        body["errors"] = errors
        return JSONResponse(body, status_code=422, media_type=PROBLEM_JSON)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "resource.not_found", 405: "method.not_allowed"}.get(exc.status_code, "http.error")
        body = _body(request, exc.status_code, code, str(exc.detail), None)
        return JSONResponse(body, status_code=exc.status_code, media_type=PROBLEM_JSON)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error on %s", request.url.path)
        body = _body(request, 500, "internal.error", "Internal server error", None)
        return JSONResponse(body, status_code=500, media_type=PROBLEM_JSON)
