"""External anchors for the audit hash chains (threat model T28, residual "tail truncation").

The hash chain detects a modified or missing *middle* entry, but not deleting the newest
entries, because the remaining chain is still internally consistent. An anchor records each
chain's head (tenant, seq, hash) somewhere the database cannot reach: an append-only JSON-lines
file on a separate volume, owned by the audit-anchor service.

Each line is:
- **chained**: ``prev`` is the SHA-256 of the previous line, so removing or editing a line breaks
  the file chain;
- **signed**: ``mac`` is HMAC-SHA256 under the anchor key, a secret the database and the API do
  not hold, so someone with database access cannot forge anchors to match a truncated chain.

On every run the service also re-checks the previous anchor against the database: each anchored
head must still exist with the same hash, and no chain may be shorter than it was. A mismatch is
logged at CRITICAL and recorded in the next line.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

VERSION = 1
GENESIS = "0" * 64


@dataclass(frozen=True)
class Head:
    tenant_id: str | None
    seq: int
    hash: str  # hex

    def key(self) -> str:
        return self.tenant_id or "platform"


@dataclass
class Anchor:
    at: str
    heads: list[Head]
    problems: list[str] = field(default_factory=list)
    prev: str = GENESIS


class AnchorFileError(ValueError):
    """The anchor file itself was edited, truncated in the middle, or signed with another key."""


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def line_digest(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()


def encode(anchor: Anchor, key: bytes) -> str:
    body: dict[str, Any] = {
        "v": VERSION,
        "at": anchor.at,
        "prev": anchor.prev,
        "heads": [{"t": h.tenant_id, "seq": h.seq, "hash": h.hash} for h in anchor.heads],
        "problems": anchor.problems,
    }
    body["mac"] = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def decode(line: str, key: bytes) -> Anchor:
    try:
        body = json.loads(line)
        mac = body.pop("mac")
    except (ValueError, KeyError, AttributeError) as exc:
        raise AnchorFileError("unreadable anchor line") from exc
    expected = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        raise AnchorFileError("anchor signature does not verify")
    if body.get("v") != VERSION:
        raise AnchorFileError("unsupported anchor version")
    return Anchor(
        at=body["at"],
        prev=body["prev"],
        problems=list(body.get("problems", [])),
        heads=[Head(h["t"], int(h["seq"]), h["hash"]) for h in body["heads"]],
    )


def read_all(path: Path, key: bytes) -> list[tuple[Anchor, str]]:
    """Every anchor with its line digest, verifying signatures and the line chain."""
    if not path.exists():
        return []
    out: list[tuple[Anchor, str]] = []
    prev = GENESIS
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        anchor = decode(raw, key)
        if anchor.prev != prev:
            raise AnchorFileError(f"anchor line {number} does not follow the previous line")
        prev = line_digest(raw)
        out.append((anchor, prev))
    return out


def read_last(path: Path, key: bytes) -> tuple[Anchor, str] | None:
    """The newest anchor and its digest (signature checked; the full chain is checked by verify)."""
    if not path.exists():
        return None
    lines = [x for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    if not lines:
        return None
    return decode(lines[-1], key), line_digest(lines[-1])


def append(path: Path, anchor: Anchor, key: bytes) -> str:
    line = encode(anchor, key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(line + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return line_digest(line)


async def current_heads(conn: AsyncConnection) -> list[Head]:
    rows = await conn.execute(text("SELECT tenant_id, seq, hash FROM audit_heads()"))
    heads = [Head(str(r.tenant_id) if r.tenant_id else None, int(r.seq), bytes(r.hash).hex()) for r in rows]
    return sorted(heads, key=lambda h: h.key())


async def check_against(conn: AsyncConnection, anchored: list[Head], current: list[Head]) -> list[str]:
    """Problems if the database no longer contains what an earlier anchor recorded."""
    problems: list[str] = []
    now = {h.key(): h for h in current}
    for h in anchored:
        head = now.get(h.key())
        if head is None or head.seq < h.seq:
            problems.append(
                f"chain {h.key()}: anchored at seq {h.seq}, database has {head.seq if head else 'no entries'}"
                " (entries were removed)"
            )
            continue
        stored = (
            await conn.execute(
                text("SELECT audit_hash_at(CAST(:t AS uuid), :s)"),
                {"t": UUID(h.tenant_id) if h.tenant_id else None, "s": h.seq},
            )
        ).scalar_one_or_none()
        if stored is None or bytes(stored).hex() != h.hash:
            problems.append(f"chain {h.key()}: entry {h.seq} no longer matches its anchor (entry was rewritten)")
    return problems


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
