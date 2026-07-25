"""Cliente HTTP async compartido: timeouts, User-Agent honesto, límite de tamaño
de respuesta y tope de requests por dominio (plan maestro §1.2, §1.4)."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "IDATA-Sentinel/1.0 (+https://idatachile.com)"
DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=10.0, write=10.0, pool=10.0)
MAX_BODY_BYTES = 5 * 1024 * 1024  # evita agotar memoria con respuestas gigantes
MAX_REDIRECTS = 10


class FetchError(str, Enum):
    """Motivo de un fetch fallido, para que los checks puedan producir el
    CheckResult correcto (plan_implementacion_escaneo_vulnerabilidades.md §4.1)."""

    UNREACHABLE = "unreachable"
    TIMEOUT = "timeout"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    REQUEST_CAP_EXCEEDED = "request_cap_exceeded"
    DISALLOWED_BY_ROBOTS = "disallowed_by_robots"


@dataclass(frozen=True)
class FetchOutcome:
    """Resultado de un fetch: nunca lanza, siempre indica éxito o el motivo del fallo.

    Es un dataclass (no estado mutable compartido) porque varios checks
    corren concurrentemente sobre el mismo HttpClient/ScanContext.
    """

    response: httpx.Response | None
    error: FetchError | None

    @property
    def ok(self) -> bool:
        return self.response is not None


@dataclass
class HttpClient:
    """Envuelve httpx.AsyncClient con las políticas del modo pasivo/auditoría.

    No aplica rate limiting: eso lo decide ScanContext, que puede reutilizar
    una sola espera para varios checks que comparten la misma respuesta cacheada.
    """

    max_requests_per_domain: int = 60
    _client: httpx.AsyncClient = field(init=False, repr=False)
    _request_counts: dict[str, int] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            follow_redirects=False,
            max_redirects=MAX_REDIRECTS,
        )

    async def get(
        self, url: str, *, headers: dict[str, str] | None = None, follow_redirects: bool = True
    ) -> FetchOutcome:
        host = urlparse(url).netloc
        count = self._request_counts.get(host, 0)
        if count >= self.max_requests_per_domain:
            logger.warning("Tope de requests alcanzado para %s (%d)", host, count)
            return FetchOutcome(response=None, error=FetchError.REQUEST_CAP_EXCEEDED)
        self._request_counts[host] = count + 1

        try:
            resp = await self._client.get(url, headers=headers, follow_redirects=follow_redirects)
        except httpx.TooManyRedirects:
            logger.info("Demasiadas redirecciones en %s", url)
            return FetchOutcome(response=None, error=FetchError.TOO_MANY_REDIRECTS)
        except (httpx.ConnectError, httpx.ConnectTimeout, OSError):
            logger.info("No se pudo conectar a %s", url)
            return FetchOutcome(response=None, error=FetchError.UNREACHABLE)
        except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout):
            logger.info("Timeout en %s", url)
            return FetchOutcome(response=None, error=FetchError.TIMEOUT)
        except httpx.HTTPError as e:
            logger.info("Error HTTP en %s: %s", url, e)
            return FetchOutcome(response=None, error=FetchError.UNREACHABLE)

        if len(resp.content) > MAX_BODY_BYTES:
            truncated = resp.content[:MAX_BODY_BYTES]
            resp = httpx.Response(
                status_code=resp.status_code,
                headers=resp.headers,
                content=truncated,
                request=resp.request,
            )
        return FetchOutcome(response=resp, error=None)

    async def post(self, url: str, *, json: dict | None = None) -> FetchOutcome:
        """Solo para notificaciones salientes del monitoreo (webhooks, §6).

        **Nunca** se usa contra un objetivo de escaneo: enviar datos a un activo
        ajeno sería un payload, y el plan lo prohíbe en ambos modos (§1.2).
        """
        try:
            resp = await self._client.post(url, json=json)
        except httpx.HTTPError as e:
            logger.info("Error enviando POST a %s: %s", url, e)
            return FetchOutcome(response=None, error=FetchError.UNREACHABLE)
        return FetchOutcome(response=resp, error=None)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
