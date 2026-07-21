"""Rate limiting para respetar el modo pasivo (plan maestro §1.2: >=2s entre requests)."""
from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Limita la frecuencia de requests por host.

    Cada host tiene su propio lock + timestamp de la última request, así
    escanear varios hosts en paralelo no se ve penalizado por el límite
    de uno solo (rate limit es por-dominio, no global al proceso).
    """

    def __init__(self, min_interval: float = 2.0) -> None:
        self.min_interval = min_interval
        self._last_request: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _lock_for(self, host: str) -> asyncio.Lock:
        lock = self._locks.get(host)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[host] = lock
        return lock

    async def wait(self, host: str) -> None:
        async with self._lock_for(host):
            now = time.monotonic()
            last = self._last_request.get(host)
            if last is not None:
                remaining = self.min_interval - (now - last)
                if remaining > 0:
                    await asyncio.sleep(remaining)
            self._last_request[host] = time.monotonic()
