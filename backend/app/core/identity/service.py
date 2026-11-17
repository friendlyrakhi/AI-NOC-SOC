"""Identity: login, MFA, sessions, tenant switching, API keys, invitations (IAM-1, IAM-5).

All functions use the identity connection (``nocsoc_auth``). Callers outside the identity
package must authorize the request before calling the mutating functions here.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from app.core import audit
from app.core.audit import Actor
from app.core.authz import service as authz
from app.core.authz.catalog import MSP_ONLY
from app.core.security import (
    API_KEY_PREFIX,
    CHALLENGE_PREFIX,
    INVITE_PREFIX,
    SESSION_PREFIX,
    hash_password,
    new_token,
    new_totp_secret,
    password_problems,
    token_hash,
    totp_uri,
    verify_password,
    verify_totp,
)
from app.errors import ProblemError
from app.mail import Mail
from app.ratelimit import login_email_key, login_ip_key
from app.services import Services

logger = logging.getLogger(__name__)

MAX_CHALLENGE_ATTEMPTS = 5


def _invalid_credentials() -> ProblemError:
    return ProblemError(401, "auth.invalid_credentials", "Invalid credentials", "Email or password is incorrect.")


def _challenge_invalid() -> ProblemError:
    return ProblemError(401, "auth.challenge_invalid", "Sign-in expired", "Start the sign-in again.")


def _mfa_invalid() -> ProblemError:
    return ProblemError(401, "auth.mfa_invalid", "Invalid code", "The authentication code is not valid.")


# ====================================================================== data
@dataclass(frozen=True)
class LoginOutcome:
    status: Literal["authenticated", "mfa_required", "mfa_enrollment_required"]
    session_token: str | None = None
    challenge_token: str | None = None


@dataclass(frozen=True)
class SessionInfo:
    id: UUID
    user_id: UUID
    email: str
    is_platform_admin: bool
    active_tenant_id: UUID | None
    aggregate: bool
    step_up_at: datetime | None
    # Established (or stepped up) with a second factor; privileged permissions need it.
    mfa: bool = False


@dataclass(frozen=True)
class ApiKeyInfo:
    id: UUID
    tenant_id: UUID
    permissions: frozenset[str]
    created_by: UUID


@dataclass(frozen=True)
class EnrollmentStart:
    secret: str
    otpauth_uri: str


@dataclass(frozen=True)
class InviteResult:
    user_id: UUID
    membership_id: UUID
    created_user: bool
    invitation_sent: bool


class IdentityService:
    def __init__(self, services: Services) -> None:
        self.s = services
        self.settings = services.settings

    # ------------------------------------------------------------------ helpers
    def _totp_aad(self, user_id: UUID) -> str:
        return f"totp:{user_id}"

    async def _create_session(
        self, conn: AsyncConnection, user_id: UUID, ip: str | None, user_agent: str | None, *, mfa: bool
    ) -> str:
        access = await authz.accessible_tenants(conn, user_id)
        active = next((a for a in access if a.access == "member"), access[0] if access else None)
        token = new_token(SESSION_PREFIX)
        await conn.execute(
            text(
                "INSERT INTO sessions (token_hash, user_id, active_tenant_id, expires_at, ip, user_agent, mfa) "
                "VALUES (:h, :u, :t, now() + make_interval(hours => :ttl), CAST(:ip AS inet), :ua, :mfa)"
            ),
            {
                "mfa": mfa,
                "h": token_hash(token),
                "u": user_id,
                "t": active.tenant_id if active else None,
                "ttl": self.settings.session_ttl_hours,
                "ip": ip,
                "ua": (user_agent or "")[:500],
            },
        )
        await conn.execute(text("UPDATE users SET last_login_at = now() WHERE id = :u"), {"u": user_id})
        return token

    async def _new_challenge(
        self, conn: AsyncConnection, user_id: UUID, purpose: str, pending_secret: str | None = None
    ) -> str:
        token = new_token(CHALLENGE_PREFIX)
        await conn.execute(
            text(
                "INSERT INTO auth_challenges (token_hash, user_id, purpose, pending_secret, expires_at) "
                "VALUES (:h, :u, :p, :s, now() + make_interval(mins => :m))"
            ),
            {
                "h": token_hash(token),
                "u": user_id,
                "p": purpose,
                "s": pending_secret,
                "m": self.settings.challenge_minutes,
            },
        )
        return token

    async def _load_challenge(self, conn: AsyncConnection, token: str, purpose: str):  # type: ignore[no-untyped-def]
        row = (
            await conn.execute(
                text(
                    "SELECT c.id, c.user_id, c.pending_secret, c.attempts, u.email "
                    "FROM auth_challenges c JOIN users u ON u.id = c.user_id "
                    "WHERE c.token_hash = :h AND c.purpose = :p AND c.used_at IS NULL "
                    "AND c.expires_at > now() AND u.status = 'active' FOR UPDATE OF c"
                ),
                {"h": token_hash(token), "p": purpose},
            )
        ).first()
        if row is None or row.attempts >= MAX_CHALLENGE_ATTEMPTS:
            return None
        return row

    # ------------------------------------------------------------------ login
    async def login(self, email: str, password: str, ip: str | None, user_agent: str | None) -> LoginOutcome:
        limiter, st = self.s.limiter, self.settings
        email_key, ip_key = login_email_key(email), login_ip_key(ip or "unknown")
        if (
            await limiter.count(email_key) >= st.login_max_failures
            or await limiter.count(ip_key) >= st.login_max_failures * 5
        ):
            async with self.s.auth_db.tx() as conn:
                await audit.append(
                    conn,
                    tenant_id=None,
                    actor=Actor("anonymous", None, ip),
                    action="auth.login",
                    outcome="denied",
                    details={"email": email, "reason": "rate_limited"},
                )
            raise ProblemError(
                429,
                "rate_limited",
                "Too many attempts",
                "Too many sign-in attempts. Try again later.",
                headers={"Retry-After": str(st.login_window_seconds)},
            )

        failure_reason: str | None = None
        outcome: LoginOutcome | None = None
        async with self.s.auth_db.tx() as conn:
            user = (
                await conn.execute(
                    text(
                        "SELECT u.id, u.status, pw.secret AS password_hash, "
                        "(totp.user_id IS NOT NULL) AS has_totp "
                        "FROM users u "
                        "LEFT JOIN user_credentials pw ON pw.user_id = u.id AND pw.kind = 'password' "
                        "LEFT JOIN user_credentials totp ON totp.user_id = u.id AND totp.kind = 'totp' "
                        "WHERE u.email = :e"
                    ),
                    {"e": email},
                )
            ).first()
            password_ok = verify_password(user.password_hash if user else None, password)
            if user is None or not password_ok:
                failure_reason = "bad_credentials"
            elif user.status != "active":
                failure_reason = "account_" + user.status
            if failure_reason or user is None:
                await audit.append(
                    conn,
                    tenant_id=None,
                    actor=Actor("anonymous", None, ip),
                    action="auth.login",
                    outcome="failure",
                    details={"email": email, "reason": failure_reason},
                )
            else:
                actor = Actor("user", user.id, ip)
                if user.has_totp:
                    outcome = LoginOutcome(
                        "mfa_required", challenge_token=await self._new_challenge(conn, user.id, "mfa")
                    )
                elif await authz.holds_privileged_anywhere(conn, user.id) or await self._is_platform_admin(
                    conn, user.id
                ):
                    outcome = LoginOutcome(
                        "mfa_enrollment_required",
                        challenge_token=await self._new_challenge(conn, user.id, "mfa_enroll"),
                    )
                else:
                    outcome = LoginOutcome(
                        "authenticated",
                        session_token=await self._create_session(conn, user.id, ip, user_agent, mfa=False),
                    )
                await audit.append(
                    conn,
                    tenant_id=None,
                    actor=actor,
                    action="auth.login",
                    outcome="success",
                    details={"next": outcome.status},
                )

        if failure_reason or outcome is None:
            await limiter.hit(email_key, st.login_window_seconds)
            await limiter.hit(ip_key, st.login_window_seconds)
            raise _invalid_credentials()
        await limiter.reset(email_key)
        return outcome

    async def _is_platform_admin(self, conn: AsyncConnection, user_id: UUID) -> bool:
        row = (await conn.execute(text("SELECT is_platform_admin FROM users WHERE id = :u"), {"u": user_id})).one()
        return bool(row.is_platform_admin)

    # ------------------------------------------------------------------ MFA
    async def verify_mfa(self, challenge: str, code: str, ip: str | None, user_agent: str | None) -> str:
        error: ProblemError | None = None
        session_token: str | None = None
        async with self.s.auth_db.tx() as conn:
            ch = await self._load_challenge(conn, challenge, "mfa")
            if ch is None:
                error = _challenge_invalid()
            else:
                cred = (
                    await conn.execute(
                        text(
                            "SELECT secret, last_used_step FROM user_credentials "
                            "WHERE user_id = :u AND kind = 'totp' FOR UPDATE"
                        ),
                        {"u": ch.user_id},
                    )
                ).one()
                secret = self.s.secrets.decrypt(cred.secret, self._totp_aad(ch.user_id))
                step = verify_totp(secret, code, cred.last_used_step)
                actor = Actor("user", ch.user_id, ip)
                if step is None:
                    await conn.execute(
                        text("UPDATE auth_challenges SET attempts = attempts + 1 WHERE id = :id"), {"id": ch.id}
                    )
                    await audit.append(conn, tenant_id=None, actor=actor, action="auth.mfa", outcome="failure")
                    error = _mfa_invalid()
                else:
                    await conn.execute(
                        text("UPDATE user_credentials SET last_used_step = :s WHERE user_id = :u AND kind = 'totp'"),
                        {"s": step, "u": ch.user_id},
                    )
                    await conn.execute(text("UPDATE auth_challenges SET used_at = now() WHERE id = :id"), {"id": ch.id})
                    session_token = await self._create_session(conn, ch.user_id, ip, user_agent, mfa=True)
                    await audit.append(conn, tenant_id=None, actor=actor, action="auth.mfa", outcome="success")
        if error or session_token is None:
            raise error or _challenge_invalid()
        return session_token

    async def start_enrollment(self, challenge: str) -> EnrollmentStart:
        async with self.s.auth_db.tx() as conn:
            ch = await self._load_challenge(conn, challenge, "mfa_enroll")
            if ch is None:
                raise _challenge_invalid()
            if ch.pending_secret:
                secret = self.s.secrets.decrypt(ch.pending_secret, f"enroll:{ch.id}")
            else:
                secret = new_totp_secret()
                await conn.execute(
                    text("UPDATE auth_challenges SET pending_secret = :s WHERE id = :id"),
                    {"s": self.s.secrets.encrypt(secret, f"enroll:{ch.id}"), "id": ch.id},
                )
            return EnrollmentStart(secret=secret, otpauth_uri=totp_uri(secret, ch.email))

    async def confirm_enrollment(self, challenge: str, code: str, ip: str | None, user_agent: str | None) -> str:
        error: ProblemError | None = None
        session_token: str | None = None
        async with self.s.auth_db.tx() as conn:
            ch = await self._load_challenge(conn, challenge, "mfa_enroll")
            if ch is None or not ch.pending_secret:
                error = _challenge_invalid()
            else:
                secret = self.s.secrets.decrypt(ch.pending_secret, f"enroll:{ch.id}")
                step = verify_totp(secret, code, None)
                actor = Actor("user", ch.user_id, ip)
                if step is None:
                    await conn.execute(
                        text("UPDATE auth_challenges SET attempts = attempts + 1 WHERE id = :id"), {"id": ch.id}
                    )
                    error = _mfa_invalid()
                else:
                    await conn.execute(
                        text(
                            "INSERT INTO user_credentials (user_id, kind, secret, last_used_step) "
                            "VALUES (:u, 'totp', :s, :step)"
                        ),
                        {
                            "u": ch.user_id,
                            "s": self.s.secrets.encrypt(secret, self._totp_aad(ch.user_id)),
                            "step": step,
                        },
                    )
                    await conn.execute(text("UPDATE auth_challenges SET used_at = now() WHERE id = :id"), {"id": ch.id})
                    session_token = await self._create_session(conn, ch.user_id, ip, user_agent, mfa=True)
                    await audit.append(conn, tenant_id=None, actor=actor, action="auth.mfa.enroll", outcome="success")
        if error or session_token is None:
            raise error or _challenge_invalid()
        return session_token

    async def step_up(self, session: SessionInfo, code: str, ip: str | None) -> None:
        error: ProblemError | None = None
        async with self.s.auth_db.tx() as conn:
            cred = (
                await conn.execute(
                    text(
                        "SELECT secret, last_used_step FROM user_credentials "
                        "WHERE user_id = :u AND kind = 'totp' FOR UPDATE"
                    ),
                    {"u": session.user_id},
                )
            ).first()
            actor = Actor("user", session.user_id, ip)
            if cred is None:
                error = ProblemError(403, "auth.mfa_not_enrolled", "MFA not enrolled", "Enroll an authenticator first.")
            else:
                secret = self.s.secrets.decrypt(cred.secret, self._totp_aad(session.user_id))
                step = verify_totp(secret, code, cred.last_used_step)
                if step is None:
                    await audit.append(conn, tenant_id=None, actor=actor, action="auth.step_up", outcome="failure")
                    error = _mfa_invalid()
                else:
                    await conn.execute(
                        text("UPDATE user_credentials SET last_used_step = :s WHERE user_id = :u AND kind = 'totp'"),
                        {"s": step, "u": session.user_id},
                    )
                    await conn.execute(
                        text("UPDATE sessions SET step_up_at = now(), mfa = true WHERE id = :id"),
                        {"id": session.id},
                    )
                    await audit.append(conn, tenant_id=None, actor=actor, action="auth.step_up", outcome="success")
        if error:
            raise error

    # ------------------------------------------------------------------ sessions
    async def resolve_session(self, token: str) -> SessionInfo | None:
        if not token.startswith(SESSION_PREFIX):
            return None
        async with self.s.auth_db.tx() as conn:
            row = (
                await conn.execute(
                    text(
                        "SELECT s.id, s.user_id, s.active_tenant_id, s.aggregate, s.step_up_at, s.mfa, "
                        "s.last_seen_at, u.email::text AS email, u.is_platform_admin "
                        "FROM sessions s JOIN users u ON u.id = s.user_id "
                        "WHERE s.token_hash = :h AND s.revoked_at IS NULL AND s.expires_at > now() "
                        "AND s.last_seen_at > now() - make_interval(mins => :idle) AND u.status = 'active'"
                    ),
                    {"h": token_hash(token), "idle": self.settings.session_idle_minutes},
                )
            ).first()
            if row is None:
                return None
            if datetime.now(UTC) - row.last_seen_at > timedelta(seconds=60):
                await conn.execute(text("UPDATE sessions SET last_seen_at = now() WHERE id = :id"), {"id": row.id})
        return SessionInfo(
            id=row.id,
            user_id=row.user_id,
            email=row.email,
            is_platform_admin=row.is_platform_admin,
            active_tenant_id=row.active_tenant_id,
            aggregate=row.aggregate,
            step_up_at=row.step_up_at,
            mfa=row.mfa,
        )

    async def logout(self, session: SessionInfo, ip: str | None) -> None:
        async with self.s.auth_db.tx() as conn:
            await conn.execute(text("UPDATE sessions SET revoked_at = now() WHERE id = :id"), {"id": session.id})
            await audit.append(conn, tenant_id=None, actor=Actor("user", session.user_id, ip), action="auth.logout")

    async def switch_tenant(self, session: SessionInfo, tenant_id: UUID, aggregate: bool, ip: str | None) -> None:
        async with self.s.auth_db.tx() as conn:
            perms = await authz.tenant_permissions(conn, session.user_id, tenant_id)
            denied = perms is None or (
                aggregate
                and (
                    perms.tenant_kind != "msp"
                    or perms.via_msp_tenant_id is not None
                    or "msp:aggregate_read" not in perms.permissions
                )
            )
            if denied:
                # Same answer whether the tenant exists or not.
                await audit.append(
                    conn,
                    tenant_id=None,
                    actor=Actor("user", session.user_id, ip),
                    action="auth.tenant.switch",
                    outcome="denied",
                    target_type="tenant",
                    target_id=str(tenant_id),
                )
            elif perms is not None:
                await conn.execute(
                    text("UPDATE sessions SET active_tenant_id = :t, aggregate = :a, step_up_at = NULL WHERE id = :id"),
                    {"t": tenant_id, "a": aggregate, "id": session.id},
                )
                await audit.append(
                    conn,
                    tenant_id=tenant_id,
                    actor=Actor("user", session.user_id, ip),
                    action="auth.tenant.switch",
                    via_tenant_id=perms.via_msp_tenant_id,
                    details={"mode": "aggregate" if aggregate else "tenant"},
                )
                if perms.via_msp_tenant_id:
                    await audit.append(
                        conn,
                        tenant_id=perms.via_msp_tenant_id,
                        actor=Actor("user", session.user_id, ip),
                        action="auth.tenant.switch",
                        target_type="tenant",
                        target_id=str(tenant_id),
                        details={"delegated_into": str(tenant_id)},
                    )
        if denied:
            raise ProblemError(404, "tenant.not_member", "Not found", "Tenant not found or not accessible.")

    # ------------------------------------------------------------------ API keys
    async def resolve_api_key(self, token: str) -> ApiKeyInfo | None:
        if not token.startswith(API_KEY_PREFIX):
            return None
        async with self.s.auth_db.tx() as conn:
            row = (
                await conn.execute(
                    text(
                        "SELECT k.id, k.tenant_id, k.permissions, k.created_by, k.last_used_at "
                        "FROM api_keys k JOIN tenants t ON t.id = k.tenant_id AND t.status = 'active' "
                        "WHERE k.key_hash = :h AND k.revoked_at IS NULL AND k.expires_at > now()"
                    ),
                    {"h": token_hash(token)},
                )
            ).first()
            if row is None:
                return None
            # A key never exceeds what its creator can still do in the tenant.
            creator = await authz.tenant_permissions(conn, row.created_by, row.tenant_id)
            if creator is None:
                return None
            if row.last_used_at is None or datetime.now(UTC) - row.last_used_at > timedelta(seconds=60):
                await conn.execute(text("UPDATE api_keys SET last_used_at = now() WHERE id = :id"), {"id": row.id})
        return ApiKeyInfo(
            id=row.id,
            tenant_id=row.tenant_id,
            permissions=frozenset(row.permissions) & creator.permissions - MSP_ONLY,
            created_by=row.created_by,
        )

    # ------------------------------------------------------------------ invitations
    async def invite_member(
        self,
        *,
        tenant_id: UUID,
        tenant_name: str,
        email: str,
        display_name: str,
        role_ids: list[UUID],
        inviter_actor: Actor,
        via_tenant_id: UUID | None = None,
    ) -> InviteResult:
        invite_token: str | None = None
        try:
            async with self.s.auth_db.tx() as conn:
                user = (await conn.execute(text("SELECT id, status FROM users WHERE email = :e"), {"e": email})).first()
                created = user is None
                if user is None:
                    user = (
                        await conn.execute(
                            text(
                                "INSERT INTO users (email, display_name, status) VALUES (:e, :n, 'invited') "
                                "RETURNING id, status"
                            ),
                            {"e": email, "n": display_name},
                        )
                    ).one()
                membership_id = (
                    await conn.execute(
                        text(
                            "INSERT INTO memberships (tenant_id, user_id, created_by) VALUES (:t, :u, :by) "
                            "ON CONFLICT (tenant_id, user_id) DO NOTHING RETURNING id"
                        ),
                        {"t": tenant_id, "u": user.id, "by": inviter_actor.actor_id},
                    )
                ).scalar_one_or_none()
                if membership_id is None:
                    raise ProblemError(409, "user.already_member", "Already a member", "This user is already a member.")
                for role_id in role_ids:
                    await conn.execute(
                        text(
                            "INSERT INTO role_bindings (tenant_id, membership_id, role_id, created_by) "
                            "VALUES (:t, :m, :r, :by)"
                        ),
                        {"t": tenant_id, "m": membership_id, "r": role_id, "by": inviter_actor.actor_id},
                    )
                if user.status == "invited":
                    invite_token = new_token(INVITE_PREFIX)
                    await conn.execute(
                        text(
                            "INSERT INTO invitations (tenant_id, user_id, token_hash, expires_at, created_by) "
                            "VALUES (:t, :u, :h, now() + make_interval(hours => :hrs), :by)"
                        ),
                        {
                            "t": tenant_id,
                            "u": user.id,
                            "h": token_hash(invite_token),
                            "hrs": self.settings.invitation_hours,
                            "by": inviter_actor.actor_id,
                        },
                    )
                await audit.append(
                    conn,
                    tenant_id=tenant_id,
                    actor=inviter_actor,
                    action="user.invite",
                    target_type="user",
                    target_id=str(user.id),
                    via_tenant_id=via_tenant_id,
                    details={"email": email, "roles": [str(r) for r in role_ids], "new_user": created},
                )
                if via_tenant_id:
                    await audit.append(
                        conn,
                        tenant_id=via_tenant_id,
                        actor=inviter_actor,
                        action="user.invite",
                        target_type="user",
                        target_id=str(user.id),
                        details={"delegated_into": str(tenant_id), "email": email},
                    )
        except IntegrityError as exc:
            raise ProblemError(
                422, "validation.failed", "Invalid role", "A role does not belong to this tenant."
            ) from exc

        if invite_token:
            link = f"{self.settings.web_base_url}/invite/accept?token={invite_token}"
            body = (
                f"You have been invited to {tenant_name} on the NOC & SOC platform.\n\n"
                f"Set your password here (valid {self.settings.invitation_hours} hours):\n{link}\n"
            )
        else:
            body = f"You have been added to {tenant_name} on the NOC & SOC platform. Sign in as usual.\n"
        await self.s.mailer.send(Mail(to=email, subject=f"Invitation to {tenant_name}", body=body))
        return InviteResult(user.id, membership_id, created, invite_token is not None)

    async def accept_invitation(self, token: str, password: str, ip: str | None) -> str:
        problems = password_problems(password)
        if problems:
            raise ProblemError(
                422,
                "validation.failed",
                "Weak password",
                "; ".join(problems),
                errors=[{"loc": ["body", "password"], "msg": p, "type": "password"} for p in problems],
            )
        async with self.s.auth_db.tx() as conn:
            inv = (
                await conn.execute(
                    text(
                        "SELECT i.id, i.tenant_id, i.user_id, u.email::text AS email, u.status FROM invitations i "
                        "JOIN users u ON u.id = i.user_id WHERE i.token_hash = :h AND i.accepted_at IS NULL "
                        "AND i.expires_at > now() FOR UPDATE OF i"
                    ),
                    {"h": token_hash(token if token.startswith(INVITE_PREFIX) else "")},
                )
            ).first()
            if inv is None or inv.status != "invited":
                raise ProblemError(
                    404, "invitation.invalid", "Invitation not valid", "The invitation is invalid or expired."
                )
            await conn.execute(
                text(
                    "INSERT INTO user_credentials (user_id, kind, secret) VALUES (:u, 'password', :s) "
                    "ON CONFLICT (user_id, kind) DO UPDATE SET secret = EXCLUDED.secret, created_at = now()"
                ),
                {"u": inv.user_id, "s": hash_password(password)},
            )
            await conn.execute(
                text("UPDATE users SET status = 'active', updated_at = now() WHERE id = :u"), {"u": inv.user_id}
            )
            await conn.execute(text("UPDATE invitations SET accepted_at = now() WHERE id = :id"), {"id": inv.id})
            await audit.append(
                conn,
                tenant_id=inv.tenant_id,
                actor=Actor("user", inv.user_id, ip),
                action="user.invitation.accept",
                target_type="user",
                target_id=str(inv.user_id),
            )
            return str(inv.email)

    # ------------------------------------------------------------------ platform
    async def create_msp_tenant(
        self, *, name: str, slug: str, admin_email: str, admin_name: str, actor: Actor
    ) -> tuple[UUID, InviteResult]:
        async with self.s.auth_db.tx() as conn:
            try:
                tenant_id = (
                    await conn.execute(
                        text("INSERT INTO tenants (kind, slug, name) VALUES ('msp', :s, :n) RETURNING id"),
                        {"s": slug, "n": name},
                    )
                ).scalar_one()
            except IntegrityError as exc:
                raise ProblemError(
                    409, "tenant.slug_taken", "Slug in use", "That tenant slug is already in use."
                ) from exc
            admin_role = (
                await conn.execute(text("SELECT id FROM roles WHERE key = 'tenant_admin' AND tenant_id IS NULL"))
            ).scalar_one()
            await audit.append(
                conn,
                tenant_id=None,
                actor=actor,
                action="platform.tenant.create",
                target_type="tenant",
                target_id=str(tenant_id),
                details={"slug": slug, "kind": "msp"},
            )
            await audit.append(
                conn, tenant_id=tenant_id, actor=actor, action="tenant.create", details={"slug": slug, "kind": "msp"}
            )
        result = await self.invite_member(
            tenant_id=tenant_id,
            tenant_name=name,
            email=admin_email,
            display_name=admin_name,
            role_ids=[admin_role],
            inviter_actor=actor,
        )
        return tenant_id, result

    async def list_all_tenants(self) -> list[dict[str, object]]:
        async with self.s.auth_db.tx() as conn:
            rows = await conn.execute(
                text(
                    "SELECT t.id, t.kind, t.slug::text AS slug, t.name, t.status, t.parent_tenant_id, t.created_at, "
                    "(SELECT count(*) FROM memberships m WHERE m.tenant_id = t.id) AS members "
                    "FROM tenants t ORDER BY t.kind, t.name"
                )
            )
            return [dict(r._mapping) for r in rows]
