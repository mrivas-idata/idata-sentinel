"""ScanContext: estado compartido de un escaneo HTTP, pasado a cada check para
evitar requests duplicados (plan_implementacion_escaneo_vulnerabilidades.md §1.3).

Vive en `core/` porque lo comparten todos los módulos que trabajan sobre HTTP
(Módulo 1 y Módulo 3): el caché de respuestas es lo que permite que dos módulos
distintos evalúen la misma página sin volver a pedirla, respetando el rate limit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

import httpx

from idata_sentinel.core.http_client import FetchOutcome, HttpClient
from idata_sentinel.core.rate_limiter import RateLimiter
from idata_sentinel.core.robots import RobotsPolicy

Mode = Literal["passive", "audit"]


@dataclass
class ScanContext:
    target: str
    host: str
    mode: Mode
    http: HttpClient
    rate_limiter: RateLimiter
    authorized: bool = False
    audit_paths: tuple[str, ...] = ()
    audit_endpoints: tuple[str, ...] = ()
    hardening_baseline: dict = field(default_factory=dict)
    robots: RobotsPolicy = field(default_factory=RobotsPolicy.empty)
    _cache: dict[tuple[str, str, bool], FetchOutcome] = field(default_factory=dict, init=False, repr=False)

    def _absolute_url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.target.rstrip('/')}{path}"

    def seed_cache(self, path: str, outcome: FetchOutcome, *, method: str = "GET", follow_redirects: bool = True) -> None:
        """Precarga una respuesta ya obtenida (p.ej. robots.txt leído antes de construir
        el contexto) para que los checks no la vuelvan a pedir."""
        self._cache[(method, path, follow_redirects)] = outcome

    async def get_outcome(
        self, path: str = "/", *, method: str = "GET", follow_redirects: bool = True
    ) -> FetchOutcome:
        key = (method, path, follow_redirects)
        if key in self._cache:
            return self._cache[key]

        if self.mode == "passive" and not self.robots.can_fetch(path):
            from idata_sentinel.core.http_client import FetchError

            outcome = FetchOutcome(response=None, error=FetchError.DISALLOWED_BY_ROBOTS)
            self._cache[key] = outcome
            return outcome

        await self.rate_limiter.wait(self.host)
        outcome = await self.http.get(self._absolute_url(path), follow_redirects=follow_redirects)
        self._cache[key] = outcome
        return outcome

    async def get(
        self, path: str = "/", *, method: str = "GET", follow_redirects: bool = True
    ) -> httpx.Response | None:
        outcome = await self.get_outcome(path, method=method, follow_redirects=follow_redirects)
        return outcome.response

    async def get_http_outcome(self, path: str = "/") -> FetchOutcome:
        """Fuerza esquema http:// sobre self.host, sin seguir redirects — usado para
        verificar si el servidor redirige forzosamente a HTTPS (checks/tls_ssl.py)."""
        key = ("GET", f"http://{path}", False)
        if key in self._cache:
            return self._cache[key]
        await self.rate_limiter.wait(self.host)
        outcome = await self.http.get(f"http://{self.host}{path}", follow_redirects=False)
        self._cache[key] = outcome
        return outcome

    def audit_targets(self, base_paths: tuple[str, ...] = ("/",)) -> tuple[str, ...]:
        """Rutas a evaluar: base + rutas de auditoría, solo si hay autorización real."""
        if self.mode == "audit" and self.authorized:
            return tuple(dict.fromkeys((*base_paths, *self.audit_paths)))
        return base_paths
