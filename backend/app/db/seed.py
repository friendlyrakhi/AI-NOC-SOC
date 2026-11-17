"""Development seed data: ``python -m app.db.seed``.

Creates one MSP with two customers, users for each role, MFA for privileged users and the
MSP's delegations (docs/08 P1, ADR-0016), plus DEMO sandbox integrations per customer
(P2). Passwords and TOTP secrets are random and are
printed once, as JSON, for scripts/dev to store in infrastructure/secrets/dev-users.json
(git-ignored). Mock data only: every address uses the reserved ``.example`` TLD.

Runs as the Postgres superuser. Refuses to run outside the dev environment.
"""

import json
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path

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
            # P5: two independent approvers (T3 actions need two people besides the requester).
            SeedUser("approver.one@globex.example", "Olu Approver (Globex)", ["approver"]),
            SeedUser("approver.two@globex.example", "Tara Approver (Globex)", ["approver"]),
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
            SeedUser("approver.one@initech.example", "Otto Approver (Initech)", ["approver"]),
            SeedUser("approver.two@initech.example", "Tess Approver (Initech)", ["approver"]),
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


# Sandbox integrations per demo tenant (P2). Names carry "DEMO" so nobody mistakes the
# simulated sources for live ones; the database only allows mode = 'sandbox' anyway.
DEMO_INTEGRATIONS: dict[str, list[str]] = {
    "globex": ["solarwinds.orion", "prometheus", "datadog", "aws.cloudwatch", "servicenow.itsm", "tenable"],
    "initech": [
        "microsoft.sentinel",
        "splunk",
        "microsoft.defender",
        "crowdstrike.falcon",
        "wazuh",
        "qualys.vmdr",
        "datadog",
        "servicenow.itsm",
    ],
}


def seed_demo_integrations(settings: Settings) -> int:
    """Idempotent: adds the demo sandbox integrations a tenant does not have yet."""
    if settings.environment != "dev":
        raise SystemExit("seeding is only allowed in the dev environment")
    from nocsoc_connectors import REGISTRY

    engine = create_engine(settings.superuser_database_url())
    created = 0
    try:
        with engine.begin() as conn:
            for slug, connectors in DEMO_INTEGRATIONS.items():
                tid = conn.execute(text("SELECT id FROM tenants WHERE slug = :s"), {"s": slug}).scalar_one_or_none()
                if tid is None:
                    continue
                for cid in connectors:
                    name = f"DEMO {REGISTRY[cid].manifest.name} (sandbox)"
                    result = conn.execute(
                        text(
                            "INSERT INTO connector_instances (tenant_id, definition_id, name, mode) "
                            "VALUES (:t, :d, :n, 'sandbox') ON CONFLICT (tenant_id, name) DO NOTHING"
                        ),
                        {"t": tid, "d": cid, "n": name},
                    )
                    if result.rowcount:
                        created += 1
                        _audit(
                            conn,
                            tid,
                            "connector.create",
                            {"definition_id": cid, "name": name, "source": "seed", "mode": "sandbox"},
                        )
    finally:
        engine.dispose()
    return created


RUNBOOKS_DIR = Path(__file__).resolve().parents[1] / "ai" / "runbooks"


def seed_demo_knowledge(settings: Settings) -> int:
    """Idempotent: loads the bundled DEMO runbooks into each demo tenant's knowledge base.

    Only documents are inserted; the API embeds them on first use through the AI gateway, so
    there is exactly one embedding implementation.
    """
    if settings.environment != "dev":
        raise SystemExit("seeding is only allowed in the dev environment")
    docs = []
    for path in sorted(RUNBOOKS_DIR.glob("*.md")):
        body = path.read_text(encoding="utf-8").strip()
        title = body.splitlines()[0].lstrip("# ").strip()
        docs.append((title, body))
    engine = create_engine(settings.superuser_database_url())
    created = 0
    try:
        with engine.begin() as conn:
            for slug in DEMO_INTEGRATIONS:
                tid = conn.execute(text("SELECT id FROM tenants WHERE slug = :s"), {"s": slug}).scalar_one_or_none()
                if tid is None:
                    continue
                for title, body in docs:
                    result = conn.execute(
                        text(
                            "INSERT INTO knowledge_docs (tenant_id, kind, title, body, source) "
                            "VALUES (:t, 'runbook', :ti, :b, 'seed (DEMO)') ON CONFLICT (tenant_id, title) DO NOTHING"
                        ),
                        {"t": tid, "ti": title, "b": body},
                    )
                    created += result.rowcount
    finally:
        engine.dispose()
    return created


def seed_missing_users(settings: Settings) -> list[dict[str, object]]:
    """Idempotent: creates seed users added in later phases (e.g. P5 approvers) in an existing
    dev database. Returns their credentials (only for users created now)."""
    if settings.environment != "dev":
        raise SystemExit("seeding is only allowed in the dev environment")
    if settings.master_key is None:
        raise SystemExit("missing secret: master_key")
    envelope = LocalEnvelopeProvider(settings.master_key.get_secret_value())
    engine = create_engine(settings.superuser_database_url())
    out: list[dict[str, object]] = []
    try:
        with engine.begin() as conn:
            roles = {r.key: r.id for r in conn.execute(text("SELECT key, id FROM roles WHERE is_system"))}
            for t in TENANTS:
                tid = conn.execute(text("SELECT id FROM tenants WHERE slug = :s"), {"s": t.slug}).scalar_one_or_none()
                if tid is None:
                    continue
                for u in t.users:
                    if conn.execute(text("SELECT 1 FROM users WHERE email = :e"), {"e": u.email}).first():
                        continue
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
                    _audit(conn, tid, "user.create", {"email": u.email, "roles": u.roles, "source": "seed"})
                    out.append({**info, "id": str(info["id"]), "tenant": t.slug, "roles": u.roles})
    finally:
        engine.dispose()
    return out


def seed_demo_playbooks(settings: Settings) -> int:
    """Idempotent: the three DEMO sample playbooks, published as version 1, per demo tenant."""
    if settings.environment != "dev":
        raise SystemExit("seeding is only allowed in the dev environment")
    from app.actions.dsl import validate_definition
    from app.actions.samples import SAMPLE_PLAYBOOKS

    engine = create_engine(settings.superuser_database_url())
    created = 0
    try:
        with engine.begin() as conn:
            for slug in DEMO_INTEGRATIONS:
                tid = conn.execute(text("SELECT id FROM tenants WHERE slug = :s"), {"s": slug}).scalar_one_or_none()
                if tid is None:
                    continue
                for pb in SAMPLE_PLAYBOOKS:
                    parsed, problems = validate_definition(pb["definition"])
                    if parsed is None:
                        raise SystemExit(f"invalid sample playbook {pb['key']}: {problems}")
                    pid = conn.execute(
                        text(
                            "INSERT INTO playbooks (tenant_id, key, name, domain, description) VALUES (:t, :k, :n, "
                            ":d, :ds) "
                            "ON CONFLICT (tenant_id, key) DO NOTHING RETURNING id"
                        ),
                        {"t": tid, "k": pb["key"], "n": pb["name"], "d": pb["domain"], "ds": pb["description"]},
                    ).scalar_one_or_none()
                    if pid is None:
                        continue
                    conn.execute(
                        text(
                            "INSERT INTO playbook_versions (tenant_id, playbook_id, version, definition, status, "
                            "published_at) "
                            "VALUES (:t, :p, 1, CAST(:d AS jsonb), 'published', now())"
                        ),
                        {"t": tid, "p": pid, "d": json.dumps(parsed.model_dump())},
                    )
                    created += 1
    finally:
        engine.dispose()
    return created


if __name__ == "__main__":
    settings = get_settings()
    result = seed(settings)
    new_users = seed_missing_users(settings) if result is None else []
    integrations = seed_demo_integrations(settings)
    runbooks = seed_demo_knowledge(settings)
    playbooks = seed_demo_playbooks(settings)
    extra = {"demo_integrations_created": integrations, "runbooks": runbooks, "playbooks": playbooks}
    if result is None:
        print(json.dumps({"status": "already_seeded", "new_users": new_users, **extra}))
        sys.exit(0)
    print(json.dumps({"status": "seeded", "users": result, **extra}, indent=2))
