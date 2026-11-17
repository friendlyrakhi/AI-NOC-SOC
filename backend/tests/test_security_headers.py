"""Every API response carries the anti-sniffing and anti-framing headers (P7, DAST finding)."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.logging_setup import RequestContextMiddleware


def test_security_headers_on_every_response() -> None:
    app = FastAPI()

    @app.get("/plain")
    def plain() -> dict[str, str]:
        return {"ok": "yes"}

    app.add_middleware(RequestContextMiddleware)
    r = TestClient(app).get("/plain")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-request-id"]
