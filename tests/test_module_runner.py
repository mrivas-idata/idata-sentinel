from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.core.rate_limiter import RateLimiter
from idata_sentinel.core.robots import RobotsPolicy
from idata_sentinel.modules.vuln_identification.context import ScanContext
from idata_sentinel.modules.vuln_identification.module import VulnIdentificationModule
from idata_sentinel.modules.vuln_identification.registry import ALL_CHECKS, checks_for_mode


class _CrashingCheck(BaseCheck):
    id = "crashing"
    category = "Test"

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        raise RuntimeError("boom")


@pytest.mark.asyncio
async def test_safe_run_contains_exceptions(make_ctx):
    ctx = make_ctx()
    module = VulnIdentificationModule()
    results = await module._safe_run(_CrashingCheck(), ctx)

    assert len(results) == 1
    assert results[0].status == "info"
    assert "crashing_error" in results[0].id


def test_checks_for_mode_returns_all_for_passive():
    checks = checks_for_mode("passive")
    assert {type(c) for c in checks} == set(ALL_CHECKS)


@pytest.mark.asyncio
@respx.mock
async def test_full_module_run_produces_conformant_contract():
    respx.get(url__regex=r"https://example\.test.*").mock(
        return_value=httpx.Response(200, headers={"Server": "nginx/1.18.0"}, text="<html></html>")
    )
    respx.get(url__regex=r"http://example\.test.*").mock(side_effect=httpx.ConnectError("no http"))

    module = VulnIdentificationModule()
    from idata_sentinel.core.engine import RunParams

    params = RunParams(
        target="https://example.test",
        host="example.test",
        mode="passive",
        http=HttpClient(),
        rate_limiter=RateLimiter(min_interval=0.0),
        authorized=False,
        authorization=None,
    )
    results = await module.run(params)

    assert results, "se esperaban hallazgos (headers de seguridad ausentes)"
    for r in results:
        assert set(r.keys()) == {
            "id", "module", "category", "severity", "likelihood", "status",
            "title", "finding", "business_impact", "recommendation", "evidence", "references",
        }
        assert r["severity"] in {"info", "low", "medium", "high", "critical"}
        assert r["likelihood"] in {"low", "medium", "high"}
        assert r["status"] in {"pass", "fail", "warning", "info"}
        assert r["module"] == "vuln_identification"


@pytest.mark.asyncio
@respx.mock
async def test_passive_mode_respects_robots_disallow(make_ctx):
    respx.get("https://example.test/admin").mock(return_value=httpx.Response(200, text="secret"))
    ctx = make_ctx(robots=RobotsPolicy.from_text("User-agent: *\nDisallow: /admin"))

    outcome = await ctx.get_outcome("/admin")

    assert outcome.response is None
    assert not respx.calls, "no debió solicitarse una ruta Disallow en modo pasivo"
