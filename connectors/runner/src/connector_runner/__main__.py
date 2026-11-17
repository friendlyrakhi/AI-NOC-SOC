"""``python -m connector_runner``: poll the platform for work and run due streams."""

import asyncio
import contextlib
import logging
import signal

from connector_runner.api import HttpPlatformApi
from connector_runner.bus import KafkaBus
from connector_runner.config import RunnerSettings
from connector_runner.scheduler import Scheduler

logger = logging.getLogger("connector_runner")


async def main() -> None:
    settings = RunnerSettings()
    if settings.runner_token is None:
        raise SystemExit("runner token secret (nocsoc_runner_token) is required")
    api = HttpPlatformApi(
        settings.api_url, settings.runner_token.get_secret_value(), verify=settings.tls_ca_file or True
    )
    bus = KafkaBus(settings.kafka_bootstrap)
    for attempt in range(30):
        try:
            await bus.start()
            break
        except Exception:
            if attempt == 29:
                raise
            await asyncio.sleep(2)
    allowlist = frozenset(h.strip().lower() for h in settings.egress_private_allowlist.split(",") if h.strip())
    scheduler = Scheduler(
        api,
        bus,
        max_pages=settings.max_pages_per_run,
        concurrency=settings.concurrency,
        live_read_enabled=settings.live_read_enabled,
        private_allowlist=allowlist,
    )
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # Windows dev shells
            loop.add_signal_handler(sig, stopping.set)
    logger.info("connector runner started (sandbox only)")
    try:
        while not stopping.is_set():
            try:
                ran = await scheduler.tick()
                if ran:
                    logger.info("ran %d stream(s)", ran)
            except Exception as exc:  # platform API briefly unavailable
                logger.warning("tick failed: %s", type(exc).__name__)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stopping.wait(), timeout=settings.poll_seconds)
    finally:
        await bus.stop()
        await api.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per poll is noise; errors still surface
    asyncio.run(main())
