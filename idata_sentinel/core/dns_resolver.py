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
class DnsAnswer:
    """Resultado de una consulta, con los tres desenlaces distinguidos.

    Devolver `((), False)` tanto para "no hay registro" como para "no pude
    consultarlo" hacía que un timeout se reportara como ausencia: así se emitió
    un `spf_missing` sobre un dominio que sí publica SPF. `failed` es lo que
    separa una observación de un fallo de medición.
    """

    values: tuple[str, ...] = ()
    nxdomain: bool = False
    failed: bool = False

    @property
    def measured(self) -> bool:
        """La consulta concluyó: los valores (aunque vacíos) son una observación."""
        return not self.failed


@dataclass(frozen=True)
class DnsRecords:
    """Snapshot DNS de un host. `nxdomain` distingue "el nombre no existe" de
    "existe pero no tiene este registro" — clave para detectar takeover.
    `unresolved` recoge los tipos que no se pudieron consultar, para que quien
    los lea no confunda "vacío" con "no medido"."""

    host: str
    records: dict[str, tuple[str, ...]] = field(default_factory=dict)
    nxdomain: bool = False
    unresolved: frozenset[str] = frozenset()

    def get(self, rtype: str) -> tuple[str, ...]:
        return self.records.get(rtype.upper(), ())

    def measured(self, rtype: str) -> bool:
        """Si la consulta de este tipo llegó a concluir."""
        return rtype.upper() not in self.unresolved

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
        self._cache: dict[tuple[str, str], DnsAnswer] = {}
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._resolver: dns.asyncresolver.Resolver | None = None

    def _get_resolver(self) -> dns.asyncresolver.Resolver:
        if self._resolver is None:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            self._resolver = resolver
        return self._resolver

    async def query(self, host: str, rtype: str) -> DnsAnswer:
        """Nunca lanza. Distingue respuesta vacía (`NoAnswer`, el registro no
        existe) de fallo de consulta (`Timeout`/`SERVFAIL`, no se pudo medir)."""
        host = host.rstrip(".").lower()
        key = (host, rtype.upper())
        if key in self._cache:
            return self._cache[key]

        answer = DnsAnswer()
        try:
            async with self._semaphore:
                response = await self._get_resolver().resolve(host, rtype)
            answer = DnsAnswer(values=tuple(_render(r) for r in response))
        except dns.resolver.NXDOMAIN:
            answer = DnsAnswer(nxdomain=True)
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            # El nombre existe pero no tiene este tipo de registro: es una
            # observación válida, no un fallo.
            answer = DnsAnswer()
        except (dns.exception.DNSException, OSError, ValueError) as e:
            logger.debug("DNS %s/%s no se pudo consultar: %s", host, rtype, e)
            answer = DnsAnswer(failed=True)

        self._cache[key] = answer
        return answer

    async def records_for(
        self, host: str, rtypes: tuple[str, ...] = INVENTORY_RECORD_TYPES
    ) -> DnsRecords:
        answers = await asyncio.gather(*(self.query(host, rt) for rt in rtypes))
        records = {rt: a.values for rt, a in zip(rtypes, answers) if a.values}
        unresolved = frozenset(rt for rt, a in zip(rtypes, answers) if a.failed)
        # NXDOMAIN solo es concluyente si *ningún* tipo devolvió datos.
        nxdomain = all(a.nxdomain for a in answers) if answers else False
        return DnsRecords(
            host=host,
            records=records,
            nxdomain=nxdomain and not records,
            unresolved=unresolved,
        )

    async def txt(self, name: str) -> DnsAnswer:
        return await self.query(name, "TXT")
