"""Scheduler de re-escaneos (plan maestro §6, §11.2 servicio `worker`).

Se apoya en `ScanStore.due_monitors()` en vez de mantener su propio estado: si el
worker se reinicia (redeploy en Railway), al arrancar recalcula qué toca y no
pierde ni duplica ejecuciones.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Awaitable, Callable

from idata_sentinel.storage.db import MonitorRecord, ScanStore, utcnow

logger = logging.getLogger(__name__)

#: Cada cuánto se revisa si hay monitores vencidos (no es la cadencia de escaneo).
DEFAULT_POLL_SECONDS = 3600


@dataclass
class MonitorScheduler:
    store: ScanStore
    run_scan: Callable[[MonitorRecord], Awaitable[None]]
    poll_seconds: float = DEFAULT_POLL_SECONDS

    async def run_due(self, *, now: str | None = None) -> list[str]:
        """Ejecuta los monitores vencidos. Un fallo en uno no detiene los demás."""
        now = now or utcnow()
        executed: list[str] = []
        for monitor in self.store.due_monitors(now=now):
            try:
                await self.run_scan(monitor)
                self.store.mark_monitor_run(monitor.target, at=now)
                executed.append(monitor.target)
            except Exception:
                logger.exception("falló el re-escaneo programado de %s", monitor.target)
        return executed

    async def serve_forever(self, *, iterations: int | None = None) -> None:
        """Bucle del worker. `iterations` acota la ejecución en los tests."""
        completed = 0
        while iterations is None or completed < iterations:
            await self.run_due()
            completed += 1
            if iterations is not None and completed >= iterations:
                break
            await asyncio.sleep(self.poll_seconds)
