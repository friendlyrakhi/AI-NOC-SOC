"""P7 optional OIDC sign-in against an in-process fake identity provider (real API, real database)."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from pydantic import SecretStr
from support.integration import Env

from app.core.identity import oidc
from app.mail import MemoryMailer
from app.main import create_app

ISSUER = "https://idp.example/realms/nocsoc"
CLIENT_ID = "nocsoc-web"
SECRET = secrets.token_hex(16)
REDIRECT = "http://web.example/auth/oidc/callback"


class FakeIdp:
    """Discovery, JWKS and a token endpoint that checks client auth, redirect URI and PKCE."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "k1"
        self.codes: dict[str, dict[str, Any]] = {}
        self.claims: dict[str, Any] = {}

    def issue(self, auth_url: str, **claims: Any) -> tuple[str, str]:
        q = {k: v[0] for k, v in parse_qs(urlparse(auth_url).query).items()}
        assert q["redirect_uri"] == REDIRECT and q["code_challenge_method"] == "S256"
        code = secrets.token_urlsafe(16)
        self.codes[code] = {"challenge": q["code_challenge"], "nonce": q["nonce"], "claims": claims}
        return code, q["state"]

    def token(self, nonce: str, claims: dict[str, Any]) -> str:
        now = int(time.time())
        body = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "u-1", "iat": now, "exp": now + 300, "nonce": nonce}
        body.update(claims)
        return jwt.encode(body, self.key, algorithm="RS256", headers={"kid": self.kid})

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": "https://idp.example/auth",
                    "token_endpoint": "https://idp.example/token",
                    "jwks_uri": "https://idp.example/jwks",
                },
            )
        if request.url.path == "/jwks":
            jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
            return httpx.Response(200, json={"keys": [{**jwk, "kid": self.kid, "use": "sig", "alg": "RS256"}]})
        if request.url.path == "/token":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            expected = "Basic " + base64.b64encode(f"{CLIENT_ID}:{SECRET}".encode()).decode()
            grant = self.codes.pop(form.get("code", ""), None)
            if request.headers.get("authorization") != expected or grant is None or form["redirect_uri"] != REDIRECT:
                return httpx.Response(400, json={"error": "invalid_grant"})
            challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest())
            if challenge.rstrip(b"=").decode() != grant["challenge"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            claims = dict(grant["claims"])
            nonce = claims.pop("_nonce", grant["nonce"])
            signer = claims.pop("_key", None)
            token = self.token(nonce, claims)
            if signer is not None:  # a token signed by someone else
                token = jwt.encode(jwt.decode(token, options={"verify_signature": False}), signer, algorithm="RS256",
                                   headers={"kid": self.kid})  # fmt: skip
            return httpx.Response(200, json={"id_token": token, "access_token": "x", "token_type": "Bearer"})
        return httpx.Response(404)


@pytest.fixture(scope="module")
def sso(env: Env) -> Iterator[tuple[TestClient, FakeIdp]]:
    settings = env.settings.model_copy(
        update={
            "oidc_enabled": True,
            "oidc_issuer": ISSUER,
            "oidc_discovery_url": "https://idp.example/realms/nocsoc/.well-known/openid-configuration",
            "oidc_client_id": CLIENT_ID,
            "oidc_client_secret": SecretStr(SECRET),
            "oidc_redirect_uri": REDIRECT,
        }
    )
    idp = FakeIdp()
    oidc._cache.clear()
    app = create_app(settings, mailer=MemoryMailer())
    with TestClient(app, base_url="http://api.example") as client:
        app.state.services.oidc_transport = httpx.MockTransport(idp.handler)
        yield client, idp
    oidc._cache.clear()


def sign_in(client: TestClient, idp: FakeIdp, **claims: Any) -> httpx.Response:
    start = client.post("/api/v1/auth/oidc/start")
    assert start.status_code == 200, start.text
    code, state = idp.issue(start.json()["authorization_url"], **claims)
    return client.post("/api/v1/auth/oidc/callback", json={"code": code, "state": state})


ADMIN = {"email": "admin@globex.example", "email_verified": True}


def test_config_reports_enabled(sso: tuple[TestClient, FakeIdp]) -> None:
    client, _ = sso
    assert client.get("/api/v1/auth/oidc/config").json() == {"enabled": True, "display_name": "Single sign-on"}


def test_sign_in_with_mfa_creates_a_full_session(sso: tuple[TestClient, FakeIdp]) -> None:
    client, idp = sso
    r = sign_in(client, idp, **ADMIN, amr=["pwd", "otp"])
    assert r.status_code == 200, r.text
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {r.json()['session_token']}"}).json()
    assert me["email"] == "admin@globex.example" and me["withheld_permissions"] == []


def test_sign_in_without_mfa_withholds_privileges(sso: tuple[TestClient, FakeIdp]) -> None:
    client, idp = sso
    r = sign_in(client, idp, **ADMIN, amr=["pwd"])
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {r.json()['session_token']}"}).json()
    assert "role:manage" in me["withheld_permissions"] and "role:manage" not in me["permissions"]


@pytest.mark.parametrize(
    ("claims", "status", "code"),
    [
        ({**ADMIN, "_nonce": "replayed-nonce"}, 401, "auth.oidc_failed"),
        ({**ADMIN, "aud": "another-client"}, 401, "auth.oidc_failed"),
        ({**ADMIN, "iss": "https://evil.example"}, 401, "auth.oidc_failed"),
        ({**ADMIN, "exp": 1}, 401, "auth.oidc_failed"),
        ({"email": "admin@globex.example", "email_verified": False}, 401, "auth.oidc_failed"),
        ({"email": "nobody@globex.example", "email_verified": True}, 403, "auth.oidc_no_account"),
        ({**ADMIN, "_key": rsa.generate_private_key(public_exponent=65537, key_size=2048)}, 401, "auth.oidc_failed"),
    ],
    ids=["nonce", "audience", "issuer", "expired", "unverified-email", "unknown-user", "forged-signature"],
)
def test_bad_id_tokens_are_refused(
    sso: tuple[TestClient, FakeIdp], claims: dict[str, Any], status: int, code: str
) -> None:
    client, idp = sso
    r = sign_in(client, idp, **claims)
    assert r.status_code == status and r.json()["code"] == code, r.text


def test_state_is_single_use(sso: tuple[TestClient, FakeIdp]) -> None:
    client, idp = sso
    start = client.post("/api/v1/auth/oidc/start").json()["authorization_url"]
    code, state = idp.issue(start, **ADMIN)
    assert client.post("/api/v1/auth/oidc/callback", json={"code": code, "state": state}).status_code == 200
    code2, _ = idp.issue(start, **ADMIN)
    r = client.post("/api/v1/auth/oidc/callback", json={"code": code2, "state": state})
    assert r.status_code == 401 and r.json()["code"] == "auth.oidc_failed"


def test_disabled_by_default(api: Any) -> None:
    r = api.client.get("/api/v1/auth/oidc/config")
    assert r.json()["enabled"] is False
    assert api.client.post("/api/v1/auth/oidc/start").json()["code"] == "auth.oidc_disabled"
