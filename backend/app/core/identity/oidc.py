"""Optional OIDC sign-in (P7, decision D7): authorization code flow with PKCE, for Keycloak or Entra ID.

The web BFF starts the flow and receives the callback; this module does everything security-relevant:
- ``start``: random state, nonce and PKCE verifier. The state is stored hashed, and nonce and verifier
  encrypted, single use, for 10 minutes. The redirect URI is the configured one, never the caller's.
- ``callback``: exchanges the code at the token endpoint (server to server, client secret plus PKCE
  verifier) and validates the ID token: signature against the IdP's JWKS with an allow-list of
  algorithms, issuer, audience, expiry and nonce.
- The sign-in maps to an existing, active platform user by verified e-mail. Nobody is provisioned
  just by signing in at the IdP: access still comes from invitations and role assignments.
- The session counts as MFA only if the IdP says so (``amr``) or the operator declares that the IdP
  enforces MFA for every sign-in (``NOCSOC_OIDC_IDP_ENFORCES_MFA``). Otherwise privileged permissions
  are withheld (MFA-bound sessions). Step-up still uses the platform authenticator.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from sqlalchemy import text

from app.core import audit
from app.core.audit import Actor
from app.core.security import token_hash
from app.errors import ProblemError
from app.services import Services

STATE_MINUTES = 10
ALGORITHMS = ["RS256", "PS256", "ES256"]
_cache: dict[str, tuple[float, Any]] = {}


def _failed(detail: str = "The single sign-on response could not be verified.") -> ProblemError:
    return ProblemError(401, "auth.oidc_failed", "Single sign-on failed", detail)


@dataclass(frozen=True)
class OidcResult:
    session_token: str
    email: str


class OidcService:
    def __init__(self, services: Services) -> None:
        self.s = services
        self.cfg = services.settings

    @property
    def enabled(self) -> bool:
        c = self.cfg
        return bool(c.oidc_enabled and c.oidc_discovery_url and c.oidc_issuer and c.oidc_client_secret)

    def _http(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=10,
            verify=self.cfg.tls_ca_file or True,
            follow_redirects=False,
            transport=self.s.oidc_transport,  # injected in tests (fake IdP)
        )

    async def _cached(self, key: str, url: str, ttl: int = 3600) -> Any:
        hit = _cache.get(key)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        async with self._http() as c:
            r = await c.get(url)
        r.raise_for_status()
        value = r.json()
        _cache[key] = (time.monotonic() + ttl, value)
        return value

    async def discovery(self) -> dict[str, Any]:
        if not self.enabled:
            raise ProblemError(404, "auth.oidc_disabled", "Single sign-on not configured", "Use your password.")
        try:
            return await self._cached("discovery", str(self.cfg.oidc_discovery_url))  # type: ignore[no-any-return]
        except httpx.HTTPError as exc:
            raise ProblemError(503, "auth.oidc_unavailable", "Identity provider unavailable", "Try again.") from exc

    # ------------------------------------------------------------------ start
    async def start(self) -> str:
        meta = await self.discovery()
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        async with self.s.auth_db.tx() as conn:
            row_id = (
                await conn.execute(
                    text(
                        "INSERT INTO oidc_states (state_hash, secret, expires_at) "
                        "VALUES (:h, '', now() + make_interval(mins => :m)) RETURNING id"
                    ),
                    {"h": token_hash(state), "m": STATE_MINUTES},
                )
            ).scalar_one()
            sealed = self.s.secrets.encrypt(json.dumps({"nonce": nonce, "verifier": verifier}), f"oidc:{row_id}")
            await conn.execute(text("UPDATE oidc_states SET secret = :s WHERE id = :id"), {"s": sealed, "id": row_id})
            await conn.execute(text("DELETE FROM oidc_states WHERE expires_at < now() - interval '1 day'"))
        query = {
            "response_type": "code",
            "client_id": self.cfg.oidc_client_id,
            "redirect_uri": self.cfg.oidc_redirect_uri,
            "scope": "openid email profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{meta['authorization_endpoint']}?{urlencode(query)}"

    # ------------------------------------------------------------------ callback
    async def callback(self, code: str, state: str, ip: str | None, user_agent: str | None) -> OidcResult:
        meta = await self.discovery()
        async with self.s.auth_db.tx() as conn:
            row = (
                await conn.execute(
                    text(
                        "UPDATE oidc_states SET used_at = now() WHERE state_hash = :h AND used_at IS NULL "
                        "AND expires_at > now() RETURNING id, secret"
                    ),
                    {"h": token_hash(state)},
                )
            ).first()
        if row is None:
            raise _failed("The sign-in link expired or was already used. Start again.")
        sealed = json.loads(self.s.secrets.decrypt(row.secret, f"oidc:{row.id}"))
        claims = await self._exchange(meta, code, sealed["verifier"], sealed["nonce"])

        email = str(claims.get("email") or "").lower()
        if not email or claims.get("email_verified") is not True:
            raise _failed("The identity provider did not return a verified e-mail address.")
        amr = {str(x) for x in claims.get("amr") or []}
        mfa = bool(amr & set(self.cfg.oidc_mfa_amr)) or self.cfg.oidc_idp_enforces_mfa

        from app.core.identity.service import IdentityService  # local: avoids an import cycle

        identity = IdentityService(self.s)
        async with self.s.auth_db.tx() as conn:
            user = (await conn.execute(text("SELECT id, status FROM users WHERE email = :e"), {"e": email})).first()
            if user is None or user.status != "active":
                await audit.append(
                    conn,
                    tenant_id=None,
                    actor=Actor("anonymous", None, ip),
                    action="auth.login",
                    outcome="failure",
                    details={"method": "oidc", "email": email, "reason": "no_active_user"},
                )
                failure = True
            else:
                token = await identity._create_session(conn, user.id, ip, user_agent, mfa=mfa)
                await audit.append(
                    conn,
                    tenant_id=None,
                    actor=Actor("user", user.id, ip),
                    action="auth.login",
                    details={"method": "oidc", "issuer": self.cfg.oidc_issuer, "mfa": mfa},
                )
                failure = False
        if failure:
            raise ProblemError(
                403,
                "auth.oidc_no_account",
                "No platform account",
                "Your organisation has not given this identity access to the platform.",
            )
        return OidcResult(session_token=token, email=email)

    async def _exchange(self, meta: dict[str, Any], code: str, verifier: str, nonce: str) -> dict[str, Any]:
        secret = self.cfg.oidc_client_secret.get_secret_value() if self.cfg.oidc_client_secret else ""
        try:
            async with self._http() as c:
                r = await c.post(
                    meta["token_endpoint"],
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": self.cfg.oidc_redirect_uri,
                        "code_verifier": verifier,
                    },
                    auth=(self.cfg.oidc_client_id, secret),
                )
        except httpx.HTTPError as exc:
            raise ProblemError(503, "auth.oidc_unavailable", "Identity provider unavailable", "Try again.") from exc
        if r.status_code != 200:
            raise _failed()
        id_token = r.json().get("id_token")
        if not id_token:
            raise _failed()
        try:
            header = jwt.get_unverified_header(id_token)
            if header.get("alg") not in ALGORITHMS:
                raise _failed()
            key = await self._signing_key(meta, str(header.get("kid", "")))
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key=key,
                algorithms=ALGORITHMS,
                audience=self.cfg.oidc_client_id,
                issuer=self.cfg.oidc_issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
                leeway=30,
            )
        except jwt.PyJWTError as exc:
            raise _failed() from exc
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise _failed()
        return claims

    async def _signing_key(self, meta: dict[str, Any], kid: str) -> Any:
        for refresh in (False, True):
            if refresh:
                _cache.pop("jwks", None)  # key rotation: fetch once more
            jwks = await self._cached("jwks", meta["jwks_uri"])
            for k in jwks.get("keys", []):
                if k.get("kid") == kid and k.get("use", "sig") == "sig":
                    return jwt.PyJWK(k).key
        raise _failed()
