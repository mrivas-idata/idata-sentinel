"""Contexto y modelo de datos del Módulo 2 — Inventario de activos (plan maestro §4).

`AssetProfile` es la unidad de inventario: un host con su DNS, su tecnología y su
exposición. La correlación de todos los perfiles es el "mapa de superficie de
ataque" que pide el §4 y que el reporte consume en su sección 5.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from idata_sentinel.checks.cloud_waf import CloudProfile
from idata_sentinel.checks.takeover import TakeoverSignal
from idata_sentinel.checks.tech_fingerprint import Detection
from idata_sentinel.core.dns_resolver import DnsRecords, DnsResolver
from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.core.rate_limiter import RateLimiter

Mode = Literal["passive", "audit"]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

#: Nombres que delatan un entorno que no debería estar expuesto a Internet.
NON_PRODUCTION_MARKERS = (
    "dev", "test", "qa", "uat", "stg", "staging", "sandbox", "demo",
    "preprod", "pre", "beta", "lab", "old", "legacy", "backup", "tmp",
)


def extract_title(html: str) -> str | None:
    match = _TITLE_RE.search(html)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:120] or None


def is_non_production(host: str) -> str | None:
    """Devuelve el marcador que hace sospechar de un entorno no productivo.

    Solo mira las etiquetas *por delante* del dominio registrable: un apex como
    `idata.test` no es un entorno de pruebas por tener ese TLD. Y compara
    etiqueta por etiqueta (no subcadena) para no marcar 'developers.x.cl' por
    contener 'dev' ni 'protest.x.cl' por contener 'test'.
    """
    labels = host.lower().split(".")
    for label in labels[:-2]:  # ignora el dominio registrable
        for part in re.split(r"[-_]", label):
            if part in NON_PRODUCTION_MARKERS:
                return part
    return None


@dataclass
class AssetProfile:
    """Fotografía de un activo. Todos los campos opcionales quedan en su valor
    neutro si el activo no resuelve o no responde: un activo no alcanzable
    sigue siendo parte del inventario."""

    host: str
    source: str = "target"  # "target" | "crt.sh" | "client"
    dns: DnsRecords | None = None
    reachable: bool = False
    scheme: str | None = None
    status_code: int | None = None
    server: str | None = None
    title: str | None = None
    technologies: tuple[Detection, ...] = ()
    cloud: CloudProfile = field(default_factory=CloudProfile)
    set_cookies: tuple[str, ...] = ()
    takeover: TakeoverSignal | None = None
    origin_leak: str | None = None
    body_snippet: str = ""

    @property
    def resolves(self) -> bool:
        return bool(self.dns and self.dns.resolves)

    @property
    def ips(self) -> tuple[str, ...]:
        return self.dns.ips if self.dns else ()

    @property
    def cnames(self) -> tuple[str, ...]:
        return self.dns.get("CNAME") if self.dns else ()

    @property
    def https(self) -> bool:
        return self.scheme == "https"

    def technology_labels(self) -> tuple[str, ...]:
        return tuple(
            f"{d.product} {d.version}" if d.version else d.product for d in self.technologies
        )

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "source": self.source,
            "resolves": self.resolves,
            "ips": list(self.ips),
            "cnames": [c.rstrip(".") for c in self.cnames],
            "reachable": self.reachable,
            "scheme": self.scheme,
            "status_code": self.status_code,
            "https": self.https,
            "server": self.server,
            "title": self.title,
            "technologies": list(self.technology_labels()),
            "cdn": list(self.cloud.cdn),
            "waf": list(self.cloud.waf),
            "cloud": list(self.cloud.cloud),
            "non_production": is_non_production(self.host),
            "takeover_service": self.takeover.service if self.takeover else None,
            "dns": self.dns.to_dict() if self.dns else None,
        }


@dataclass
class AssetInventoryContext:
    """Estado compartido del Módulo 2. A diferencia del `ScanContext` del Módulo 1,
    aquí el eje no es la ruta sino el **activo**: cada host se toca una sola vez."""

    target: str
    host: str
    mode: Mode
    http: HttpClient
    rate_limiter: RateLimiter
    dns: DnsResolver
    authorized: bool = False
    allowed_domains: tuple[str, ...] = ()
    additional_assets: tuple[str, ...] = ()
    max_assets: int = 25

    def in_scope(self, host: str) -> bool:
        """Los activos aportados por el cliente solo se tocan si caen dentro de
        los dominios autorizados (§1.1 scope enforcement)."""
        host = host.lower().rstrip(".")
        domains = self.allowed_domains or (self.host,)
        return any(
            host == d.lower().rstrip(".") or host.endswith("." + d.lower().rstrip("."))
            for d in domains
        )
