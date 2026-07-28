"""Descubrimiento pasivo de subdominios (plan maestro §4 — Módulo 2).

Fuente: Certificate Transparency logs (RFC 6962) vía crt.sh. Es lectura de un
registro público y auditable — no hay fuerza bruta de nombres ni diccionarios,
lo que mantiene el descubrimiento dentro del modo pasivo (§1.2).
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

from idata_sentinel.core.domains import registrable_domain
from idata_sentinel.core.http_client import HttpClient

#: Consulta por el dominio a secas. La forma comodín anterior
#: (`?q=%25.{domain}`, que llega a crt.sh como `%.dominio`) devuelve HTTP 404:
#: el servicio dejó de aceptarla. Sin comodín, la respuesta trae el árbol
#: completo del dominio, incluido el apex.
CRT_SH_URL = "https://crt.sh/?q={domain}&output=json"

#: Tope de activos a perfilar. Cada uno cuesta consultas DNS + un GET, y el
#: rate limit del modo pasivo es de >=2s por host (§1.2).
DEFAULT_MAX_SUBDOMAINS = 25

#: crt.sh consulta una base enorme y con frecuencia tarda más que un sitio web
#: normal. Con el timeout estándar de 10s el descubrimiento fallaba a menudo.
CRT_SH_TIMEOUT = 30.0

#: crt.sh es intermitente por naturaleza: en pruebas sobre un mismo dominio
#: alternó 200, 404, 502 y timeout en cuestión de minutos. Sin reintento, el
#: inventario quedaba incompleto por una indisponibilidad de segundos.
CRT_SH_ATTEMPTS = 3
CRT_SH_BACKOFF_SECONDS = 2.0

#: Códigos que justifican reintentar: indisponibilidad temporal del servicio.
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


@dataclass(frozen=True)
class DiscoveredAsset:
    host: str
    source: str  # "target" | "crt.sh" | "client"


@dataclass(frozen=True)
class DiscoveryResult:
    """Distingue "no hay subdominios" de "no pude averiguarlo".

    Devolver una lista vacía en ambos casos hacía que un fallo de crt.sh
    produjera un inventario incompleto sin que nadie lo notara: el cliente
    leería "1 activo descubierto" y creería que esa es toda su superficie.
    """

    hosts: list[str]
    ok: bool = True
    reason: str = ""


def parse_crtsh(payload: str, domain: str, *, limit: int = DEFAULT_MAX_SUBDOMAINS) -> list[str]:
    """Función pura: separada del I/O para poder testearla sin red."""
    try:
        entries = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(entries, list):
        return []

    domain = domain.lower().rstrip(".")
    names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for raw in str(entry.get("name_value", "")).split("\n"):
            name = raw.strip().lower().rstrip(".")
            # Los certificados wildcard aparecen como '*.dominio': el comodín no
            # es un activo en sí, pero el nombre base que lo acompaña sí lo es.
            if name.startswith("*."):
                name = name[2:]
            if not name or "*" in name or " " in name:
                continue
            if name == domain or name.endswith("." + domain):
                names.add(name)

    # Los nombres más cortos son los activos "principales": priorizarlos al truncar.
    return sorted(names, key=lambda n: (n.count("."), len(n), n))[:limit]


async def discover_subdomains(
    http: HttpClient,
    domain: str,
    *,
    limit: int = DEFAULT_MAX_SUBDOMAINS,
    attempts: int | None = None,
    backoff: float | None = None,
) -> DiscoveryResult:
    """Nunca lanza: es descubrimiento, no un check. Ante cualquier problema el
    escaneo continúa con el dominio principal, pero el resultado deja constancia
    de que la fuente no estuvo disponible.

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

    reason = "crt.sh no respondió"
    for attempt in range(1, max(1, attempts) + 1):
        outcome = await http.get(CRT_SH_URL.format(domain=apex), timeout=CRT_SH_TIMEOUT)

        if not outcome.ok:
            motivo = outcome.error.value if outcome.error else "desconocido"
            reason = f"crt.sh no respondió ({motivo})"
        elif outcome.response.status_code == 200:
            hosts = parse_crtsh(outcome.response.text, apex, limit=limit)
            if not hosts and outcome.response.text.strip() not in ("[]", ""):
                return DiscoveryResult([], ok=False, reason="crt.sh devolvió una respuesta ilegible")
            return DiscoveryResult(hosts)
        elif outcome.response.status_code in _RETRYABLE_STATUS:
            reason = f"crt.sh devolvió HTTP {outcome.response.status_code}"
        else:
            # 404 y demás respuestas definitivas: reintentar no cambia nada.
            return DiscoveryResult(
                [], ok=False, reason=f"crt.sh devolvió HTTP {outcome.response.status_code}"
            )

        if attempt < attempts and backoff > 0:
            await asyncio.sleep(backoff * attempt)

    return DiscoveryResult([], ok=False, reason=f"{reason} tras {attempts} intento(s)")
