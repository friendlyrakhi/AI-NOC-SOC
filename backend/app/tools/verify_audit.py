"""Verify the audit log against its external anchors: ``python -m app.tools.verify_audit``.

Run by ``scripts/verify-audit`` in the one-shot ``audit-verify`` container (superuser, anchor
volume mounted read-only). Checks, in order:
1. every chain recomputes (``audit_verify``): no modified or missing middle entries;
2. the anchor file: every line's signature verifies and every line follows the previous one;
3. every anchored head in the newest anchor is still in the database with the same hash, so no
   tail was truncated or rewritten since it was anchored.
Exit code 0 when everything holds, 1 otherwise. Prints no audit content.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.config import Settings, get_settings
from app.core import anchors


async def verify(settings: Settings) -> list[str]:
    problems: list[str] = []
    if settings.audit_anchor_key is None:
        return ["the audit anchor key secret is not available"]
    key = settings.audit_anchor_key.get_secret_value().strip().encode()
    engine = create_async_engine(settings.superuser_database_url())
    try:
        async with engine.begin() as conn:
            chains = [r[0] for r in await conn.execute(text("SELECT DISTINCT tenant_id FROM audit_log"))]
            for tenant in chains:
                r = (await conn.execute(text("SELECT * FROM audit_verify(:t)"), {"t": tenant})).one()
                label = str(tenant) if tenant else "platform"
                if r.ok:
                    print(f"chain {label}: ok ({r.checked} entries)")
                else:
                    problems.append(f"chain {label}: broken at seq {r.first_bad_seq} ({r.reason})")
            try:
                history = anchors.read_all(Path(settings.audit_anchor_path), key)
            except anchors.AnchorFileError as exc:
                return [*problems, f"anchor file: {exc}"]
            if not history:
                problems.append("no anchors written yet (is the audit-anchor service running?)")
                return problems
            print(f"anchor file: ok ({len(history)} signed lines, newest {history[-1][0].at})")
            for anchor, _ in history:
                problems += [f"recorded at {anchor.at}: {p}" for p in anchor.problems]
            heads = await anchors.current_heads(conn)
            problems += await anchors.check_against(conn, history[-1][0].heads, heads)
    finally:
        await engine.dispose()
    return problems


def main() -> int:
    problems = asyncio.run(verify(get_settings()))
    for p in problems:
        print(f"PROBLEM: {p}")
    print("audit verification " + ("FAILED" if problems else "passed"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
