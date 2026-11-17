"""Synthetic load-test tenant (P7, NFR-1): ``python -m app.tools.seed_load``.

Creates (once) a standalone tenant ``loadtest`` labelled SYNTHETIC (kind msp, with no customers or
delegations, so no other tenant's views change), a reader user without a
password (it cannot sign in), and N synthetic alerts plus incidents spread over 30 days. It prints a
fresh read-only API key for that tenant, valid for one day, on stdout as JSON. The demo tenants are not
touched, and ``--remove`` deletes the tenant and everything in it from Postgres.

Dev environment only; runs as the superuser in the one-shot ``migrate`` container.
"""

from __future__ import annotations

import argparse
import json
import sys

from sqlalchemy import create_engine, text

from app.config import get_settings
from app.core.security import API_KEY_PREFIX, new_token, token_hash

SLUG = "loadtest"
READER = "loadtest.reader@loadtest.invalid"
READ_PERMISSIONS = [
    "alert:read",
    "incident:read",
    "asset:read",
    "service:read",
    "search:read",
    "analytics:read",
    "audit:read",
]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--alerts", type=int, default=100_000)
    p.add_argument("--incidents", type=int, default=2_000)
    p.add_argument("--remove", action="store_true")
    args = p.parse_args()
    settings = get_settings()
    if settings.environment != "dev":
        raise SystemExit("the load-test tenant is only allowed in the dev environment")
    engine = create_engine(settings.superuser_database_url())
    try:
        with engine.begin() as conn:
            if args.remove:
                conn.execute(text("DELETE FROM tenants WHERE slug = :s"), {"s": SLUG})
                conn.execute(text("DELETE FROM users WHERE email = :e"), {"e": READER})
                print(json.dumps({"removed": SLUG}))
                return 0
            tenant = conn.execute(text("SELECT id FROM tenants WHERE slug = :s"), {"s": SLUG}).scalar()
            if tenant is None:
                tenant = conn.execute(
                    text(
                        "INSERT INTO tenants (kind, slug, name) VALUES ('msp', :s, 'Load test (SYNTHETIC)') "
                        "RETURNING id"
                    ),
                    {"s": SLUG},
                ).scalar_one()
            user = conn.execute(text("SELECT id FROM users WHERE email = :e"), {"e": READER}).scalar()
            if user is None:
                user = conn.execute(
                    text(
                        "INSERT INTO users (email, display_name, status) "
                        "VALUES (:e, 'Load test reader (SYNTHETIC)', 'active') RETURNING id"
                    ),
                    {"e": READER},
                ).scalar_one()
                conn.execute(
                    text("INSERT INTO memberships (tenant_id, user_id) VALUES (:t, :u)"), {"t": tenant, "u": user}
                )
            # The key is limited to READ_PERMISSIONS, but never exceeds its creator: give the synthetic,
            # password-less user (it cannot sign in) a role that holds those read permissions.
            member = conn.execute(
                text("SELECT id FROM memberships WHERE tenant_id = :t AND user_id = :u"), {"t": tenant, "u": user}
            ).scalar_one()
            role = conn.execute(text("SELECT id FROM roles WHERE is_system AND key = 'tenant_admin'")).scalar_one()
            conn.execute(
                text(
                    "INSERT INTO role_bindings (tenant_id, membership_id, role_id) SELECT :t, :m, :r "
                    "WHERE NOT EXISTS (SELECT 1 FROM role_bindings WHERE membership_id = :m AND role_id = :r)"
                ),
                {"t": tenant, "m": member, "r": role},
            )
            existing = conn.execute(text("SELECT count(*) FROM alerts WHERE tenant_id = :t"), {"t": tenant}).scalar()
            missing = max(0, args.alerts - int(existing or 0))
            if missing:
                # Shape: 2/3 NOC and 1/3 SOC, mixed severities and states, 500 hosts, last 30 days.
                conn.execute(
                    text(
                        """
                        INSERT INTO alerts (tenant_id, domain, connector_id, source_alert_id, fingerprint, title,
                          description, severity, status, category, service_hint, first_seen, last_seen,
                          occurrence_count, labels, sandbox)
                        SELECT :t,
                          CASE WHEN g % 3 = 0 THEN 'soc' ELSE 'noc' END,
                          'loadtest.synthetic', 'load-' || (g + :o), 'load-' || (g + :o),
                          '[SYNTHETIC] ' || (ARRAY['CPU saturation','Link down','Disk latency','Failed logins',
                                                    'Malware detected','Service unreachable'])[1 + g % 6]
                            || ' on host-' || (g % 500),
                          'Synthetic alert generated for the NFR-1 load test.',
                          (ARRAY['critical','high','medium','low','info'])[1 + (g * 7) % 5],
                          (ARRAY['new','acknowledged','in_progress','resolved','closed'])[1 + (g * 3) % 5],
                          'loadtest', 'svc-' || (g % 40),
                          now() - make_interval(secs => (g * 26) % 2592000),
                          now() - make_interval(secs => (g * 13) % 2592000),
                          1 + g % 4, '{"synthetic": true}'::jsonb, true
                        FROM generate_series(1, :n) AS g
                        """
                    ),
                    {"t": tenant, "n": missing, "o": int(existing or 0)},
                )
            have = conn.execute(text("SELECT count(*) FROM incidents WHERE tenant_id = :t"), {"t": tenant}).scalar()
            if int(have or 0) < args.incidents:
                conn.execute(
                    text(
                        """
                        INSERT INTO incidents (tenant_id, number, domain, title, severity, priority, status,
                          detected_at, created_by_type)
                        SELECT :t, 'LT-' || lpad((g + :o)::text, 6, '0'),
                          CASE WHEN g % 3 = 0 THEN 'soc' ELSE 'noc' END,
                          '[SYNTHETIC] Load-test incident #' || (g + :o),
                          (ARRAY['critical','high','medium','low'])[1 + g % 4],
                          (ARRAY['P1','P2','P3','P4'])[1 + g % 4],
                          (ARRAY['open','investigating','contained','resolved','closed'])[1 + g % 5],
                          now() - make_interval(secs => (g * 1297) % 2592000), 'user'
                        FROM generate_series(1, :n) AS g
                        """
                    ),
                    {"t": tenant, "n": args.incidents - int(have or 0), "o": int(have or 0)},
                )
            key = new_token(API_KEY_PREFIX)
            conn.execute(
                text(
                    "INSERT INTO api_keys (tenant_id, name, prefix, key_hash, permissions, expires_at, created_by) "
                    "VALUES (:t, 'k6 load test (temporary)', :p, :h, :perms, now() + interval '1 day', :u)"
                ),
                {"t": tenant, "p": key[:12], "h": token_hash(key), "perms": READ_PERMISSIONS, "u": user},
            )
            counts = {
                "alerts": int(
                    conn.execute(text("SELECT count(*) FROM alerts WHERE tenant_id = :t"), {"t": tenant}).scalar_one()
                ),
                "incidents": int(
                    conn.execute(
                        text("SELECT count(*) FROM incidents WHERE tenant_id = :t"), {"t": tenant}
                    ).scalar_one()
                ),
            }
    finally:
        engine.dispose()
    print(json.dumps({"tenant_id": str(tenant), "api_key": key, **counts}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
