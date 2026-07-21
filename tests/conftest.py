from __future__ import annotations

import pytest

from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.core.rate_limiter import RateLimiter
from idata_sentinel.core.robots import RobotsPolicy
from idata_sentinel.modules.vuln_identification.context import ScanContext


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
