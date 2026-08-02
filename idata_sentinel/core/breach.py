"""Proveedor de OSINT de filtraciones de datos (Tier 1.3).

**Off por defecto.** A diferencia del resto del escaneo —que solo lee lo que el
objetivo publica— consultar filtraciones toca un servicio externo (Have I Been
Pwned). Por eso solo se activa si hay una API key configurada
(`IDATA_HIBP_API_KEY`); sin ella, el check es un no-op y el escaneo sigue siendo
100% offline.

**Límite legal/técnico honesto:** la búsqueda por dominio de HIBP exige verificar
la propiedad del dominio y una suscripción. Es decir, sirve para **clientes** que
autorizan y controlan su dominio, no para prospección de dominios ajenos. La
herramienta lo refleja: es una capacidad de auditoría con el cliente, no un truco
de prospección.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

import httpx

ENV_HIBP_KEY = "IDATA_HIBP_API_KEY"
_HIBP_BASE = "https://haveibeenpwned.com/api/v3"
_USER_AGENT = "IDATA-Sentinel/1.0 (+https://idatachile.com)"


@dataclass(frozen=True)
class BreachSummary:
    """Resumen agregado. NUNCA contiene los correos/credenciales concretos: solo
    el conteo y los nombres públicos de las brechas."""

    account_count: int
    breach_names: tuple[str, ...]


class BreachProvider(Protocol):
    async def domain_breaches(self, domain: str) -> BreachSummary | None: ...


@dataclass
class HibpProvider:
    api_key: str
    base_url: str = _HIBP_BASE

    async def domain_breaches(self, domain: str) -> BreachSummary | None:
        headers = {"hibp-api-key": self.api_key, "User-Agent": _USER_AGENT}
        url = f"{self.base_url}/breacheddomain/{domain}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code == 404:
            return BreachSummary(0, ())  # dominio sin cuentas en brechas conocidas
        resp.raise_for_status()
        # HIBP devuelve {alias: [nombres_de_brecha]}. Se agrega sin guardar aliases.
        data = resp.json() or {}
        names: set[str] = set()
        for breach_list in data.values():
            names.update(breach_list or [])
        return BreachSummary(account_count=len(data), breach_names=tuple(sorted(names)))


def resolve_provider(env: dict | None = None) -> BreachProvider | None:
    """Devuelve el proveedor configurado, o `None` si no hay API key (caso por
    defecto → el check no corre y no hay tráfico externo)."""
    env = env if env is not None else os.environ
    key = (env.get(ENV_HIBP_KEY) or "").strip()
    return HibpProvider(api_key=key) if key else None
