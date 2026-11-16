"""Development seed data: ``python -m app.db.seed``.

Creates one MSP with two customers, users for each role, MFA for privileged users and the
MSP's delegations (docs/08 P1, ADR-0016). Passwords and TOTP secrets are random and are
printed once, as JSON, for scripts/dev to store in infrastructure/secrets/dev-users.json
(git-ignored). Mock data only: every address uses the reserved ``.example`` TLD.

Runs as the Postgres superuser. Refuses to run outside the dev environment.
"""

import json
import secrets
import sys
from dataclasses import dataclass, field

from sqlalchemy import Connection, create_engine, text

from app.config import Settings, get_settings
from app.core.authz.catalog import PRIVILEGED, SYSTEM_ROLES
from app.core.secrets import LocalEnvelopeProvider
from app.core.security import hash_password, new_totp_secret


@dataclass
class SeedUser:
    email: str
    name: str
    roles: list[str]
    platform_admin: bool = False


@dataclass
class SeedTenant:
    slug: str
    name: str
    kind: str
    users: list[SeedUser] = field(default_factory=list)
    parent: str | None = None


TENANTS = [
    SeedTenant(
        "acme-msp",
        "Acme Managed Services",
        "msp",
        [
            SeedUser("msp.admin@acme.example", "Alex Admin (Acme)", ["tenant_admin"]),
            SeedUser("msp.noc@acme.example", "Noah NOC (Acme)", ["noc_analyst"]),
            SeedUser("msp.soc@acme.example", "Sam SOC (Acme)", ["soc_analyst_l1"]),
            SeedUser("msp.exec@acme.example", "Erin Exec (Acme)", ["executive_viewer"]),
        ],
    ),
    SeedTenant(
        "globex",
        "Globex Corporation",
        "customer",
        [
            SeedUser("admin@globex.example", "Gail Admin (Globex)", ["tenant_admin"]),
            SeedUser("noc@globex.example", "Gus Engineer (Globex)", ["noc_engineer"]),
            SeedUser("auditor@globex.example", "Ada Auditor (Globex)", ["auditor"]),
        ],
        parent="acme-msp",
    ),
    SeedTenant(
        "initech",
        "Initech",
        "customer",
        [
            SeedUser("admin@initech.example", "Ian Admin (Initech)", ["tenant_admin"]),
            SeedUser("soc@initech.example", "Ivy Responder (Initech)", ["soc_analyst_l2"]),
        ],
        parent="acme-msp",
    ),
]

PLATFORM_ADMIN = SeedUser("platform.admin@nocsoc.example", "Pat Platform", [], platform_admin=True)

# (MSP role, customer slug, customer role, aggregate_read)
DELEGATIONS = [
    ("tenant_admin", "globex", "tenant_admin", True),
    ("tenant_admin", "initech", "tenant_admin", True),
    ("noc_analyst", "globex", "noc_analyst", True),
    ("soc_analyst_l1", "initech", "soc_analyst_l1", True),
    ("executive_viewer", "globex", "executive_viewer", True),
    ("executive_viewer", "initech", "executive_viewer", True),
]

_ROLE_PERMS = {r.key: r.permissions for r in SYSTEM_ROLES}


def _needs_mfa(user: SeedUser) -> bool:
    return user.platform_admin or any(_ROLE_PERMS[r] & PRIVILEGED for r in user.roles)


def _password() -> str:
    return "Dev-" + secrets.token_urlsafe(12)


def _create_user(conn: Connection, envelope: LocalEnvelopeProvider, user: SeedUser) -> dict[str, object]:
    user_id = conn.execute(
        text(
            "INSERT INTO users (email, display_name, status, is_platform_admin) "
            "VALUES (:e, :n, 'active', :pa) RETURNING id"
        ),
        {"e": user.email, "n": user.name, "pa": user.platform_admin},
    ).scalar_one()
    password = _password()
    conn.execute(
        text("INSERT INTO user_credentials (user_id, kind, secret) VALUES (:u, 'password', :s)"),
        {"u": user_id, "s": hash_password(password)},
    )
    totp = None
    if _needs_mfa(user):
        totp = new_totp_secret()
        conn.execute(
            text("INSERT INTO user_credentials (user_id, kind, secret) VALUES (:u, 'totp', :s)"),
            {"u": user_id, "s": envelope.encrypt(totp, f"totp:{user_id}")},
        )
    return {"id": user_id, "email": user.email, "password": password, "totp_secret": totp}


def _audit(conn: Connection, tenant_id: object, action: str, details: dict[str, object]) -> None:
    conn.execute(
        text(
            "SELECT audit_append(:t, 'system', NULL, NULL, NULL, :a, 'tenant', CAST(:t AS text), 'success', "
            "CAST(:d AS jsonb), NULL)"
        ),
        {"t": tenant_id, "a": action, "d": json.dumps(details)},
    )


def seed(settings: Settings) -> list[dict[str, object]] | None:
    if settings.environment != "dev":
        raise SystemExit("seeding is only allowed in the dev environment")
    if settings.master_key is None:
        raise SystemExit("missing secret: master_key")
    envelope = LocalEnvelopeProvider(settings.master_key.get_secret_value())
    engine = create_engine(settings.superuser_database_url())
    out: list[dict[str, object]] = []
    try:
        with engine.begin() as conn:
            if conn.execute(text("SELECT 1 FROM tenants WHERE slug = 'acme-msp'")).first():
                return None
            roles = {r.key: r.id for r in conn.execute(text("SELECT key, id FROM roles WHERE is_system"))}
            tenant_ids: dict[str, object] = {}
            for t in TENANTS:
                tid = conn.execute(
                    text(
                        "INSERT INTO tenants (kind, parent_tenant_id, slug, name) VALUES (:k, :p, :s, :n) RETURNING id"
                    ),
                    {"k": t.kind, "p": tenant_ids.get(t.parent or ""), "s": t.slug, "n": t.name},
                ).scalar_one()
                tenant_ids[t.slug] = tid
                _audit(conn, tid, "tenant.create", {"slug": t.slug, "kind": t.kind, "source": "seed"})
                for u in t.users:
                    info = _create_user(conn, envelope, u)
                    mid = conn.execute(
                        text("INSERT INTO memberships (tenant_id, user_id) VALUES (:t, :u) RETURNING id"),
                        {"t": tid, "u": info["id"]},
                    ).scalar_one()
                    for role in u.roles:
                        conn.execute(
                            text("INSERT INTO role_bindings (tenant_id, membership_id, role_id) VALUES (:t, :m, :r)"),
                            {"t": tid, "m": mid, "r": roles[role]},
                        )
                    out.append({**info, "id": str(info["id"]), "tenant": t.slug, "roles": u.roles})
            msp = tenant_ids["acme-msp"]
            for msp_role, customer, customer_role, agg in DELEGATIONS:
                conn.execute(
                    text(
                        "INSERT INTO delegations (msp_tenant_id, customer_tenant_id, msp_role_id, customer_role_id, "
                        "aggregate_read) VALUES (:m, :c, :mr, :cr, :agg)"
                    ),
                    {
                        "m": msp,
                        "c": tenant_ids[customer],
                        "mr": roles[msp_role],
                        "cr": roles[customer_role],
                        "agg": agg,
                    },
                )
                _audit(
                    conn,
                    tenant_ids[customer],
                    "delegation.create",
                    {"msp": "acme-msp", "msp_role": msp_role, "customer_role": customer_role, "source": "seed"},
                )
            info = _create_user(conn, envelope, PLATFORM_ADMIN)
            out.append({**info, "id": str(info["id"]), "tenant": None, "roles": ["platform_admin"]})
    finally:
        engine.dispose()
    return out


if __name__ == "__main__":
    result = seed(get_settings())
    if result is None:
        print(json.dumps({"status": "already_seeded"}))
        sys.exit(0)
    print(json.dumps({"status": "seeded", "users": result}, indent=2))
