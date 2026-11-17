"""Structured (JSON) logging with a per-request correlation ID.

- Every record is one JSON object: time, level, logger, message, request_id, plus ``extra``.
- ``X-Request-ID`` from the caller is accepted if it is a short token, otherwise a new one is
  generated; it is echoed on the response and included in every log line of the request.
- Access lines record the route *template* (``/alerts/{alert_id}``), never query strings,
  bodies or headers, so tokens and personal data stay out of logs (threat model T17).
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.telemetry import current_trace_id

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

_VALID_ID = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_STANDARD = set(vars(logging.makeLogRecord({}))) | {"message", "asctime"}


class SecretScrubber:
    """Last line of defence against credentials in logs (threat model T17, SEC-SEC-01).

    Applied to the final formatted line, so it also covers exception text and ``extra`` fields:
    - known secret values (the process's own configured secrets) are replaced outright;
    - token shapes this platform issues (``nss_`` sessions, ``nsk_`` API keys, ``whs_`` webhook
      secrets), bearer headers and ``password=...``-style pairs are masked by pattern.
    """

    _PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"\b(nss|nsk|whs)_[A-Za-z0-9_\-]{8,}"), r"\1_[redacted]"),
        (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=\-]{8,}"), "Bearer [redacted]"),
        (
            re.compile(
                r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization)(\\?[\"']?\s*[:=]\s*\\?[\"']?)([^\"'\s,;}&\\]{4,})"
            ),
            r"\1\2[redacted]",
        ),
    )

    def __init__(self) -> None:
        self._known: set[str] = set()

    def register(self, *values: str | None) -> None:
        for v in values:
            if v and len(v) >= 8:
                self._known.add(v)

    def __call__(self, text: str) -> str:
        for value in sorted(self._known, key=len, reverse=True):
            if value in text:
                text = text.replace(value, "[redacted]")
        for pattern, repl in self._PATTERNS:
            text = pattern.sub(repl, text)
        return text


scrubber = SecretScrubber()


class ScrubbingTextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return scrubber(super().format(record))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return scrubber(self._format(record))

    def _format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        trace_id = current_trace_id()
        if trace_id:
            out["trace_id"] = trace_id
        for key, value in vars(record).items():
            if key not in _STANDARD and not key.startswith("_"):
                out[key] = value
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def configure_logging(level: int = logging.INFO, *, json_format: bool = True, settings: Any = None) -> None:
    """``settings``: every ``SecretStr`` field on it is registered with the scrubber."""
    if settings is not None:
        from pydantic import SecretStr

        scrubber.register(*(v.get_secret_value() for v in vars(settings).values() if isinstance(v, SecretStr)))
    root = logging.getLogger()
    handler = logging.StreamHandler()
    handler.setFormatter(
        JsonFormatter() if json_format else ScrubbingTextFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root.handlers[:] = [handler]
    root.setLevel(level)
    # httpx logs full URLs (which may carry query parameters); keep it at WARNING.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").disabled = True  # replaced by the access line below


class RequestContextMiddleware:
    """Pure ASGI middleware: correlation ID + one structured access line per request."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.log = logging.getLogger("app.access")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = dict(scope.get("headers") or []).get(b"x-request-id", b"").decode("latin-1")
        rid = incoming if _VALID_ID.match(incoming) else uuid.uuid4().hex
        token = request_id_var.set(rid)
        start = time.perf_counter()
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message.setdefault("headers", [])
                # Every API response (P7, DAST): no MIME sniffing, never framed.
                present = {k.lower() for k, _ in message["headers"]}
                extra = [(b"x-request-id", rid.encode())]
                if b"x-content-type-options" not in present:
                    extra.append((b"x-content-type-options", b"nosniff"))
                if b"x-frame-options" not in present:
                    extra.append((b"x-frame-options", b"DENY"))
                message["headers"] = [*message["headers"], *extra]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            route = scope.get("route")
            self.log.info(
                "request",
                extra={
                    "method": scope.get("method"),
                    "route": getattr(route, "path", None) or "unmatched",
                    "status": status,
                    "duration_ms": round((time.perf_counter() - start) * 1000, 1),
                    "tenant_id": str(getattr(scope.get("state", {}).get("principal"), "tenant_id", "") or "") or None,
                },
            )
            request_id_var.reset(token)
