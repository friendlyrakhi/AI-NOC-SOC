"""Fixed-window counters in Valkey (threat model T1, T31).

Keys are namespaced: ``p:`` for platform-level counters, ``t:{tenant_id}:`` for tenant
counters (threat model T9). Identifiers are hashed so emails and IPs are not stored in clear.
"""

import hashlib

import redis.asyncio as redis


def _h(value: str) -> str:
    return hashlib.sha256(value.lower().encode()).hexdigest()[:32]


def login_email_key(email: str) -> str:
    return f"p:login:email:{_h(email)}"


def login_ip_key(ip: str) -> str:
    return f"p:login:ip:{_h(ip)}"


class RateLimiter:
    def __init__(self, client: redis.Redis) -> None:
        self._r = client

    async def count(self, key: str) -> int:
        value = await self._r.get(key)
        return int(value) if value else 0

    async def hit(self, key: str, window_seconds: int) -> int:
        async with self._r.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, window_seconds, nx=True)
            count, _ = await pipe.execute()
        return int(count)

    async def reset(self, key: str) -> None:
        await self._r.delete(key)
