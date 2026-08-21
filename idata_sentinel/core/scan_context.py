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
from idata_sentinel.core.interstitial import InterstitialSignal
from idata_sentinel.core.rate_limiter import RateLimiter
from idata_sentinel.core.robots import RobotsPolicy
from idata_sentinel.core.session import ClientSession

Mode = Literal["passive", "audit"]


def _headers_key(headers: dict[str, str] | None) -> str:
    """Firma estable de las cabeceras extra, para distinguir en el caché una
    petición con `Origin`/sesión de la misma ruta pedida sin ellas."""
    if not headers:
        return ""
    return ";".join(f"{k.lower()}={v}" for k, v in sorted(headers.items()))


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
    #: Señal de página intersticial anti-bot detectada en la raíz. Si está
    #: presente, lo que respondió el servidor no es el sitio y los checks que
    #: dependen del contenido se declaran no evaluables (`core/interstitial.py`).
    interstitial: InterstitialSignal | None = None
    #: Gate de activación de capacidades activas (plan activo §4). Defaults
    #: seguros: sin ids habilitados y sin confirmación, ningún check activo corre.
    active_checks: frozenset[str] = field(default_factory=frozenset)
    active_acknowledged: bool = False
    #: Sesión provista por el cliente para escaneo autenticado (§7). `None` = anónimo.
    client_session: ClientSession | None = None
    #: Rastreo acotado de páginas, poblado solo por el módulo de visibilidad
    #: (`core/crawl.py`). Los checks SEO/GEO lo consumen en vez de rastrear cada
    #: uno por su cuenta, que multiplicaría las peticiones por número de checks.
    crawl: object | None = None
    #: Baseline de hardening ya compilado, cacheado para no recompilar por check.
    _compiled_baseline: object | None = field(default=None, init=False, repr=False)
    _cache: dict[tuple[str, str, bool], FetchOutcome] = field(default_factory=dict, init=False, repr=False)

    def _absolute_url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.target.rstrip('/')}{path}"

    @staticmethod
    def _key(
        path: str, *, method: str, follow_redirects: bool,
        authenticated: bool = False, headers: dict[str, str] | None = None,
    ) -> tuple[str, str, bool]:
        return (f"{method}|{authenticated}|{_headers_key(headers)}", path, follow_redirects)

    def seed_cache(self, path: str, outcome: FetchOutcome, *, method: str = "GET", follow_redirects: bool = True) -> None:
        """Precarga una respuesta ya obtenida (p.ej. robots.txt leído antes de construir
        el contexto) para que los checks no la vuelvan a pedir."""
        self._cache[self._key(path, method=method, follow_redirects=follow_redirects)] = outcome

    def active_enabled(self, check) -> bool:
        """Único punto de verdad que un check activo consulta antes de actuar
        (plan activo §4.4). Un check no-activo siempre pasa; uno activo exige el
        modo audit autorizado, la doble confirmación y estar habilitado por nombre."""
        if not getattr(check, "active", False):
            return True
        return (
            self.mode == "audit"
            and self.authorized
            and self.active_acknowledged
            and getattr(check, "id", None) in self.active_checks
        )

    def _session_headers(self, url: str, *, authenticated: bool) -> dict[str, str] | None:
        """Cabecera de sesión para `url`, solo si (a) se pidió autenticada, (b) hay
        sesión y (c) el host cae en el scope de la sesión. La intersección con
        `allowed_domains` la garantiza el engine al construir la sesión."""
        if not authenticated or self.client_session is None:
            return None
        return self.client_session.header_for(url)

    async def get_outcome(
        self,
        path: str = "/",
        *,
        method: str = "GET",
        follow_redirects: bool = True,
        headers: dict[str, str] | None = None,
        authenticated: bool = False,
    ) -> FetchOutcome:
        # La sesión y las cabeceras extra hacen única la respuesta: entran en la
        # clave de caché para no confundir la petición anónima con la autenticada.
        cache_key = self._key(
            path, method=method, follow_redirects=follow_redirects,
            authenticated=authenticated, headers=headers,
        )
        if cache_key in self._cache:
            return self._cache[cache_key]

        if self.mode == "passive" and not self.robots.can_fetch(path):
            from idata_sentinel.core.http_client import FetchError

            outcome = FetchOutcome(response=None, error=FetchError.DISALLOWED_BY_ROBOTS)
            self._cache[cache_key] = outcome
            return outcome

        url = self._absolute_url(path)
        merged: dict[str, str] = dict(headers or {})
        session_headers = self._session_headers(url, authenticated=authenticated)
        if session_headers:
            merged.update(session_headers)

        await self.rate_limiter.wait(self.host)
        outcome = await self.http.request(
            url, method=method, follow_redirects=follow_redirects,
            headers=merged or None,
        )
        self._cache[cache_key] = outcome
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
