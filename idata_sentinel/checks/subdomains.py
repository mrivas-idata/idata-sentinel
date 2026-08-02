"""Descubrimiento pasivo de subdominios (plan maestro §4 — Módulo 2).

Fuente: Certificate Transparency logs (RFC 6962). Es lectura de un registro
público y auditable — no hay fuerza bruta de nombres ni diccionarios, lo que
mantiene el descubrimiento dentro del modo pasivo (§1.2).

Se consultan **dos registros independientes en paralelo** (crt.sh y certspotter)
y se fusionan sus respuestas. La razón es empírica: crt.sh es intermitente y con
una sola fuente el módulo se quedaba sin inventario justo cuando ese servicio
estaba caído. Medido sobre un objetivo real con crt.sh devolviendo 502, la
segunda fuente aportó 17 subdominios donde el informe decía "1 activo" — el
mapa de superficie, que es el artefacto más comercial del módulo, salía vacío
sin que nadie lo notara.

Paralelo y no cascada: dos fuentes lentas en serie duplicarían la espera, y la
fusión aprovecha que cada registro ve un subconjunto distinto de certificados.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from idata_sentinel.core.domains import registrable_domain
from idata_sentinel.core.http_client import HttpClient

if TYPE_CHECKING:
    from idata_sentinel.core.subdomain_cache import SubdomainCache

logger = logging.getLogger(__name__)

#: Consulta por el dominio a secas. La forma comodín anterior
#: (`?q=%25.{domain}`, que llega a crt.sh como `%.dominio`) devuelve HTTP 404:
#: el servicio dejó de aceptarla. Sin comodín, la respuesta trae el árbol
#: completo del dominio, incluido el apex.
CRT_SH_URL = "https://crt.sh/?q={domain}&output=json"

#: certspotter expone el mismo dato con otra API. Sin API key el servicio limita
#: las consultas por hora: suficiente para prospección puntual, pero si se
#: engancha al monitoreo continuo (§6) habrá que registrar una key gratuita.
CERTSPOTTER_URL = (
    "https://api.certspotter.com/v1/issuances"
    "?domain={domain}&include_subdomains=true&expand=dns_names"
)

#: Tercera fuente: HackerTarget (CSV `host,ip`, gratis, sin key). Reduce la
#: probabilidad de que las tres caigan a la vez —el fallo que dejaba el inventario
#: vacío—. Su plan gratuito tiene tope diario; al excederlo responde 200 con un
#: texto de error, que el parser detecta y trata como fuente caída.
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"

#: Tope de activos a perfilar. Cada uno cuesta consultas DNS + un GET, y el
#: rate limit del modo pasivo es de >=2s por host (§1.2).
DEFAULT_MAX_SUBDOMAINS = 25

#: Los registros de CT consultan bases enormes y con frecuencia tardan más que
#: un sitio web normal. Con el timeout estándar de 10s el descubrimiento fallaba
#: a menudo.
CRT_SH_TIMEOUT = 30.0

#: Ambos servicios son intermitentes: en pruebas sobre un mismo dominio crt.sh
#: alternó 200, 404, 502 y timeout en cuestión de minutos. Sin reintento, el
#: inventario quedaba incompleto por una indisponibilidad de segundos.
CRT_SH_ATTEMPTS = 3
CRT_SH_BACKOFF_SECONDS = 2.0

#: Códigos que justifican reintentar: indisponibilidad temporal o límite de tasa.
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True)
class DiscoveredAsset:
    host: str
    source: str  # "target" | "crt.sh" | "certspotter" | "client"


@dataclass(frozen=True)
class SourceOutcome:
    """Qué pasó con un registro concreto. Se reporta por fuente para que
    "inventario parcial" no se confunda con "inventario completo y pequeño"."""

    name: str
    ok: bool
    count: int = 0
    reason: str = ""


@dataclass(frozen=True)
class DiscoveryResult:
    """Distingue "no hay subdominios" de "no pude averiguarlo".

    Devolver una lista vacía en ambos casos hacía que un fallo del registro
    produjera un inventario incompleto sin que nadie lo notara: el cliente
    leería "1 activo descubierto" y creería que esa es toda su superficie.
    """

    hosts: list[str]
    ok: bool = True
    reason: str = ""
    sources: tuple[SourceOutcome, ...] = ()
    #: host -> registro(s) donde apareció, para la columna ORIGEN del informe.
    host_sources: dict[str, str] = field(default_factory=dict)
    #: Nombres distintos que vieron los registros, **antes** de aplicar el tope.
    #: Sin esto el truncado también mentía: sobre un objetivo real los registros
    #: devolvieron 39 nombres y el informe presentaba 25 como si fueran todos.
    total_known: int = 0
    #: Cuántos de los hosts provienen SOLO del caché (escaneos previos), no
    #: confirmados por ninguna fuente en vivo en esta corrida.
    from_cache: int = 0

    @property
    def truncated(self) -> int:
        return max(0, self.total_known - len(self.hosts))

    @property
    def complete(self) -> bool:
        """Todas las fuentes respondieron. Con una caída el inventario sigue
        siendo útil, pero ya no se puede presentar como exhaustivo."""
        return bool(self.sources) and all(source.ok for source in self.sources)

    @property
    def failed_sources(self) -> tuple[SourceOutcome, ...]:
        return tuple(source for source in self.sources if not source.ok)


# -- parseo (funciones puras, testeables sin red) ---------------------------


def _collect(raw_names, domain: str) -> set[str]:
    domain = domain.lower().rstrip(".")
    names: set[str] = set()
    for raw in raw_names:
        name = str(raw).strip().lower().rstrip(".")
        # Los certificados wildcard aparecen como '*.dominio': el comodín no
        # es un activo en sí, pero el nombre base que lo acompaña sí lo es.
        if name.startswith("*."):
            name = name[2:]
        if not name or "*" in name or " " in name:
            continue
        if name == domain or name.endswith("." + domain):
            names.add(name)
    return names


def _rank(names: set[str], limit: int) -> list[str]:
    """Los nombres más cortos son los activos "principales": priorizarlos al truncar."""
    return sorted(names, key=lambda n: (n.count("."), len(n), n))[:limit]


def _entries(payload: str) -> list | None:
    """Lista de entradas, o `None` si la respuesta no es interpretable."""
    try:
        entries = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        return None
    return entries if isinstance(entries, list) else None


def _crtsh_names(payload: str, domain: str) -> set[str] | None:
    entries = _entries(payload)
    if entries is None:
        return None
    raw: list[str] = []
    for entry in entries:
        if isinstance(entry, dict):
            raw.extend(str(entry.get("name_value", "")).split("\n"))
    return _collect(raw, domain)


def _certspotter_names(payload: str, domain: str) -> set[str] | None:
    entries = _entries(payload)
    if entries is None:
        return None  # p.ej. {"code": "rate_limited"}: objeto, no lista
    raw: list[str] = []
    for entry in entries:
        if isinstance(entry, dict):
            raw.extend(entry.get("dns_names") or ())
    return _collect(raw, domain)


def _hackertarget_names(payload: str, domain: str) -> set[str] | None:
    """CSV `host,ip` por línea. Al exceder el tope diario el servicio responde 200
    con un texto de error ('API count exceeded…'): se distingue de 'sin
    subdominios' (respuesta válida vacía) para no dar un 0 en falso ni marcar como
    caída una respuesta legítima que contenga la palabra 'error' en un host."""
    text = (payload or "").strip()
    raw = [line.split(",", 1)[0] for line in text.splitlines() if line.strip()]
    names = _collect(raw, domain)
    if names:
        return names
    lowered = text.lower()
    if "api count exceeded" in lowered or "error" in lowered:
        return None  # mensaje de límite/error: fuente caída, no "sin subdominios"
    return set()  # respuesta válida sin subdominios del dominio


def parse_crtsh(payload: str, domain: str, *, limit: int = DEFAULT_MAX_SUBDOMAINS) -> list[str]:
    names = _crtsh_names(payload, domain)
    return _rank(names, limit) if names else []


def parse_certspotter(
    payload: str, domain: str, *, limit: int = DEFAULT_MAX_SUBDOMAINS
) -> list[str]:
    names = _certspotter_names(payload, domain)
    return _rank(names, limit) if names else []


# -- consulta ---------------------------------------------------------------


async def _query_source(
    http: HttpClient,
    *,
    name: str,
    url: str,
    parser,
    domain: str,
    attempts: int,
    backoff: float,
) -> tuple[set[str], SourceOutcome]:
    """Consulta un registro con reintentos. Nunca lanza: devuelve lo que obtuvo
    y el motivo si no obtuvo nada."""
    reason = f"{name} no respondió"

    for attempt in range(1, max(1, attempts) + 1):
        outcome = await http.get(url, timeout=CRT_SH_TIMEOUT)

        if not outcome.ok:
            motivo = outcome.error.value if outcome.error else "desconocido"
            reason = f"{name} no respondió ({motivo})"
        elif outcome.response.status_code == 200:
            names = parser(outcome.response.text, domain)
            if names is None:
                return set(), SourceOutcome(
                    name, ok=False, reason=f"{name} devolvió una respuesta ilegible"
                )
            return names, SourceOutcome(name, ok=True, count=len(names))
        elif outcome.response.status_code in _RETRYABLE_STATUS:
            reason = f"{name} devolvió HTTP {outcome.response.status_code}"
        else:
            # 404 y demás respuestas definitivas: reintentar no cambia nada.
            return set(), SourceOutcome(
                name, ok=False, reason=f"{name} devolvió HTTP {outcome.response.status_code}"
            )

        if attempt < attempts and backoff > 0:
            await asyncio.sleep(backoff * attempt)

    return set(), SourceOutcome(name, ok=False, reason=f"{reason} tras {attempts} intento(s)")


async def discover_subdomains(
    http: HttpClient,
    domain: str,
    *,
    limit: int = DEFAULT_MAX_SUBDOMAINS,
    attempts: int | None = None,
    backoff: float | None = None,
    cache: "SubdomainCache | None" = None,
) -> DiscoveryResult:
    """Nunca lanza: es descubrimiento, no un check. Ante cualquier problema el
    escaneo continúa con el dominio principal, pero el resultado deja constancia
    de qué registros no estuvieron disponibles.

    Consulta siempre el **dominio registrable**: los certificados se emiten bajo
    él, no bajo el host. Escanear `https://www.cliente.cl` preguntando por
    `www.cliente.cl` devolvía cero subdominios, y el informe presentaba "1
    activo" como si esa fuera toda la superficie del cliente.
    """
    # Se resuelven en tiempo de llamada, no como valor por defecto, para que
    # ajustar la política de reintento (p. ej. anular la espera en los tests)
    # no exija tocar cada sitio de llamada.
    attempts = CRT_SH_ATTEMPTS if attempts is None else attempts
    backoff = CRT_SH_BACKOFF_SECONDS if backoff is None else backoff

    apex = registrable_domain(domain)
    if not apex:
        return DiscoveryResult([], ok=False, reason="dominio no interpretable")

    registries = (
        ("crt.sh", CRT_SH_URL, _crtsh_names),
        ("certspotter", CERTSPOTTER_URL, _certspotter_names),
        ("hackertarget", HACKERTARGET_URL, _hackertarget_names),
    )

    gathered = await asyncio.gather(
        *(
            _query_source(
                http, name=name, url=url.format(domain=apex), parser=parser,
                domain=apex, attempts=attempts, backoff=backoff,
            )
            for name, url, parser in registries
        ),
        return_exceptions=True,
    )

    merged: set[str] = set()
    origins: dict[str, list[str]] = {}
    outcomes: list[SourceOutcome] = []

    for (name, _, _), result in zip(registries, gathered):
        if isinstance(result, BaseException):  # red de seguridad: nunca propagar
            logger.exception("consulta a %s falló", name, exc_info=result)
            outcomes.append(
                SourceOutcome(name, ok=False, reason=f"error interno: {type(result).__name__}")
            )
            continue
        names, outcome = result
        outcomes.append(outcome)
        merged |= names
        for host in names:
            origins.setdefault(host, []).append(name)

    responded = [o for o in outcomes if o.ok]

    # Red de seguridad ante la caída total de las fuentes: completar con lo
    # descubierto en corridas anteriores. El caché aporta el NOMBRE; el módulo lo
    # vuelve a perfilar, así que un subdominio ya eliminado aparecerá como "no
    # resuelve" en esta corrida, no como un falso positivo.
    from_cache = 0
    if cache is not None:
        if responded:
            # Persistir solo lo confirmado en vivo, para no acumular indefinidamente.
            cache.update(apex, merged)
        cached = cache.known(apex)
        only_cached = cached - merged
        from_cache = len(only_cached)
        for host in only_cached:
            origins.setdefault(host, []).append("escaneo previo")
        merged |= cached

    hosts = _rank(merged, limit)
    failures = [o.reason for o in outcomes if not o.ok]

    return DiscoveryResult(
        hosts=hosts,
        # Basta con que un registro conteste, o que el caché aporte nombres, para
        # tener inventario: solo si nada de eso ocurre se declara fallido.
        ok=bool(responded) or bool(merged),
        reason="; ".join(failures),
        sources=tuple(outcomes),
        host_sources={host: ", ".join(sources) for host, sources in origins.items()},
        total_known=len(merged),
        from_cache=from_cache,
    )
