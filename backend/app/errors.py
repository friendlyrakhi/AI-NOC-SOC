"""RFC 9457 problem details (docs/05-api-specification.md §1)."""

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

PROBLEM_JSON = "application/problem+json"

# OpenAPI (P7): every error is an RFC 9457 problem document. The generated document describes
# them, so clients and the API fuzzer can check error responses as strictly as successes.
PROBLEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "title": "Problem",
    "required": ["type", "title", "status", "code"],
    "properties": {
        "type": {"type": "string"},
        "title": {"type": "string"},
        "status": {"type": "integer"},
        "detail": {"type": ["string", "null"]},
        "instance": {"type": ["string", "null"]},
        "code": {"type": "string", "description": "Stable machine-readable error code"},
        "errors": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"loc": {"type": "array"}, "msg": {"type": "string"}, "type": {"type": "string"}},
            },
        },
    },
}


def document_problems(schema: dict[str, Any]) -> dict[str, Any]:
    """Replaces FastAPI's default 422 description and adds 4XX/503 problem responses everywhere."""
    schema.setdefault("components", {}).setdefault("schemas", {})["Problem"] = PROBLEM_SCHEMA
    for name in ("HTTPValidationError", "ValidationError"):
        schema["components"]["schemas"].pop(name, None)
    content = {PROBLEM_JSON: {"schema": {"$ref": "#/components/schemas/Problem"}}}
    for item in schema.get("paths", {}).values():
        for method, op in item.items():
            if method not in {"get", "put", "post", "patch", "delete"}:
                continue
            responses = op.setdefault("responses", {})
            responses["422"] = {"description": "Validation failed", "content": content}
            responses.setdefault("4XX", {"description": "Problem details (RFC 9457)", "content": content})
            responses.setdefault(
                "503",
                {"description": "A dependency is not configured or not reachable", "content": content},
            )
    return schema


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
