from __future__ import annotations

import pytest

from idata_sentinel.core.dns_resolver import DnsAnswer, DnsResolver
from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.core.rate_limiter import RateLimiter
from idata_sentinel.core.robots import RobotsPolicy
from idata_sentinel.modules.vuln_identification.context import ScanContext


class FakeDnsResolver(DnsResolver):
    """Zona DNS en memoria. Hereda de `DnsResolver` y solo sustituye `query()`,
    así `records_for()`/`txt()` ejercitan el código real sin tocar la red."""

    def __init__(
        self,
        zone: dict[tuple[str, str], tuple[str, ...]] | None = None,
        nxdomains: tuple[str, ...] = (),
        unresolvable: tuple[tuple[str, str], ...] = (),
    ) -> None:
        super().__init__()
        self.zone = {(h.lower(), t.upper()): v for (h, t), v in (zone or {}).items()}
        self.nxdomains = {h.lower() for h in nxdomains}
        #: Pares (host, rtype) que simulan un timeout: la consulta no concluye.
        #: Permite ejercitar la distinción entre ausencia y fallo de medición.
        self.unresolvable = {(h.lower(), t.upper()) for h, t in unresolvable}
        self.queries: list[tuple[str, str]] = []

    async def query(self, host: str, rtype: str) -> DnsAnswer:
        host = host.rstrip(".").lower()
        rtype = rtype.upper()
        self.queries.append((host, rtype))
        if (host, rtype) in self.unresolvable:
            return DnsAnswer(failed=True)
        if host in self.nxdomains:
            return DnsAnswer(nxdomain=True)
        return DnsAnswer(values=self.zone.get((host, rtype), ()))


@pytest.fixture
def fake_dns():
    return FakeDnsResolver


@pytest.fixture
def fast_rate_limiter() -> RateLimiter:
    return RateLimiter(min_interval=0.0)


@pytest.fixture
def http_client() -> HttpClient:
    return HttpClient()


@pytest.fixture
def make_ctx(fast_rate_limiter, http_client):
    def _make(
        target: str = "https://example.test",
        mode: str = "passive",
        authorized: bool = False,
        audit_paths: tuple[str, ...] = (),
        audit_endpoints: tuple[str, ...] = (),
        hardening_baseline: dict | None = None,
        robots: RobotsPolicy | None = None,
    ) -> ScanContext:
        return ScanContext(
            target=target,
            host="example.test",
            mode=mode,
            http=http_client,
            rate_limiter=fast_rate_limiter,
            authorized=authorized,
            audit_paths=audit_paths,
            audit_endpoints=audit_endpoints,
            hardening_baseline=hardening_baseline or {},
            robots=robots or RobotsPolicy.empty(),
        )

    return _make
