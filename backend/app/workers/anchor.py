"""Audit anchor service: ``python -m app.workers.anchor`` (threat model T28).

Periodically writes each audit chain's head to a signed, chained JSON-lines file on its own
volume (see ``app.core.anchors``) and re-checks the previous anchor against the database.
It runs as the RLS-bound worker role and can only call ``audit_heads()``/``audit_hash_at()``:
it never reads audit content. Only this service holds the anchor key and mounts the anchor
volume read-write; the API cannot reach either.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import time
from pathlib import Path

from app import telemetry
from app.config import Settings, get_settings
from app.core import anchors
from app.db.engines import AppDatabase
from app.logging_setup import configure_logging

logger = logging.getLogger("app.workers.anchor")


class AnchorService:
    def __init__(self, settings: Settings, db: AppDatabase | None = None) -> None:
        if settings.audit_anchor_key is None:
            raise SystemExit("audit anchor key secret is required")
        self.key = settings.audit_anchor_key.get_secret_value().strip().encode()
        if len(self.key) < 32:
            raise SystemExit("audit anchor key must be at least 32 characters")
        self.path = Path(settings.audit_anchor_path)
        self.settings = settings
        self.db = db or AppDatabase(settings, url=settings.worker_database_url())
        self.stopping = asyncio.Event()
        self._last_write = 0.0

    def _previous(self) -> tuple[anchors.Anchor | None, str, list[str]]:
        """(last anchor, digest of the last line, problems reading it)."""
        if not self.path.exists():
            return None, anchors.GENESIS, []
        lines = [x for x in self.path.read_text(encoding="utf-8").splitlines() if x.strip()]
        if not lines:
            return None, anchors.GENESIS, []
        digest = anchors.line_digest(lines[-1])
        try:
            return anchors.decode(lines[-1], self.key), digest, []
        except anchors.AnchorFileError as exc:
            return None, digest, [f"anchor file: {exc}"]

    async def run_once(self, *, force: bool = False) -> list[str]:
        """Checks the last anchor and appends a new one when heads changed, something is wrong,
        or the heartbeat is due. Returns the problems found."""
        previous, prev_digest, problems = self._previous()
        async with self.db.engine.begin() as conn:
            heads = await anchors.current_heads(conn)
            if previous is not None:
                problems += await anchors.check_against(conn, previous.heads, heads)
        telemetry.ANCHOR_RUNS.add(1)
        if problems:
            telemetry.ANCHOR_PROBLEMS.add(len(problems))
        for p in problems:
            logger.critical("audit anchor check failed: %s", p)
        changed = previous is None or previous.heads != heads
        heartbeat = time.monotonic() - self._last_write >= self.settings.audit_anchor_heartbeat_seconds
        if force or changed or problems or heartbeat:
            anchors.append(
                self.path,
                anchors.Anchor(at=anchors.now_iso(), heads=heads, problems=problems, prev=prev_digest),
                self.key,
            )
            self._last_write = time.monotonic()
            logger.info("audit anchor written (%d chains, %d problems)", len(heads), len(problems))
        return problems

    async def run(self) -> None:
        logger.info("audit anchor service started (file=%s)", self.path)
        try:
            while not self.stopping.is_set():
                try:
                    await self.run_once()
                except Exception as exc:  # keep anchoring; the next run retries
                    logger.error("audit anchor run failed: %s", type(exc).__name__)
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self.stopping.wait(), self.settings.audit_anchor_interval_seconds)
        finally:
            await self.db.dispose()


async def main(settings: Settings | None = None) -> None:
    settings = settings or get_settings()
    telemetry.setup("nocsoc-audit-anchor", settings)
    service = AnchorService(settings)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, service.stopping.set)
    try:
        await service.run()
    finally:
        telemetry.shutdown()


if __name__ == "__main__":
    configure_logging(settings=get_settings())
    asyncio.run(main())
