"""Resolución DNS async (plan maestro §2: `dnspython`).

Sigue la misma filosofía que `http_client.py`: **nunca lanza**, siempre devuelve
un resultado explícito. Se inyecta como dependencia para que los tests corran
100% offline (plan_implementacion_escaneo_vulnerabilidades.md §5.5).
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0

#: Tipos inventariados por el Módulo 2 (plan maestro §4) + CNAME, necesario
#: para la detección de subdominios colgantes (`checks/takeover.py`).
INVENTORY_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "CAA")


def _render(rdata: object) -> str:
    """TXT llega troceado en strings de <=255 bytes: hay que reunirlas para no
    partir un SPF/DMARC largo por la mitad."""
    strings = getattr(rdata, "strings", None)
    if strings is not None:
        return b"".join(strings).decode("utf-8", errors="replace")
    return str(rdata)


@dataclass(frozen=True)
class DnsRecords:
    """Snapshot DNS de un host. `nxdomain` distingue "el nombre no existe" de
    "existe pero no tiene este registro" — clave para detectar takeover."""

    host: str
    records: dict[str, tuple[str, ...]] = field(default_factory=dict)
    nxdomain: bool = False

    def get(self, rtype: str) -> tuple[str, ...]:
        return self.records.get(rtype.upper(), ())

    @property
    def resolves(self) -> bool:
        return bool(self.get("A") or self.get("AAAA"))

    @property
    def ips(self) -> tuple[str, ...]:
        return (*self.get("A"), *self.get("AAAA"))

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "records": {k: list(v) for k, v in self.records.items() if v},
            "nxdomain": self.nxdomain,
        }


class DnsResolver:
    """Wrapper async sobre dnspython. Cachea por (host, rtype) dentro de un
    escaneo: varios activos pueden compartir NS/MX y no tiene sentido repetir."""

    def __init__(self, *, timeout: float = DEFAULT_TIMEOUT, max_concurrency: int = 10) -> None:
        self.timeout = timeout
        self._cache: dict[tuple[str, str], tuple[tuple[str, ...], bool]] = {}
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._resolver: dns.asyncresolver.Resolver | None = None

    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        if self._resolver is None:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            self._resolver = resolver
        return self._resolver

    async def query(self, host: str, rtype: str) -> tuple[tuple[str, ...], bool]:
        """Devuelve (valores, nxdomain). Ante cualquier fallo: ((), False)."""
        host = host.rstrip(".").lower()
        key = (host, rtype.upper())
        if key in self._cache:
            return self._cache[key]

        values: tuple[str, ...] = ()
        nxdomain = False
        try:
            async with self._semaphore:
                answer = await self._get_resolver().resolve(host, rtype)
            values = tuple(_render(r) for r in answer)
        except dns.resolver.NXDOMAIN:
            nxdomain = True
        except (dns.exception.DNSException, OSError, ValueError) as e:
            logger.debug("DNS %s/%s falló: %s", host, rtype, e)

        self._cache[key] = (values, nxdomain)
        return values, nxdomain

    async def records_for(
        self, host: str, rtypes: tuple[str, ...] = INVENTORY_RECORD_TYPES
    ) -> DnsRecords:
        results = await asyncio.gather(*(self.query(host, rt) for rt in rtypes))
        records = {rt: values for rt, (values, _) in zip(rtypes, results) if values}
        # NXDOMAIN solo es concluyente si *ningún* tipo devolvió datos.
        nxdomain = all(nx for _, nx in results) if results else False
        return DnsRecords(host=host, records=records, nxdomain=nxdomain and not records)

    async def txt(self, name: str) -> tuple[str, ...]:
        values, _ = await self.query(name, "TXT")
        return values
