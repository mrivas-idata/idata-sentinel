"""OSINT de filtraciones (Tier 1.3): opt-in por API key, off por defecto."""
from __future__ import annotations

import httpx
import respx

from idata_sentinel.checks.breach import BreachExposureCheck
from idata_sentinel.core.breach import BreachSummary, HibpProvider, resolve_provider


# -- cliente HIBP (parseo de la respuesta) ----------------------------------


@respx.mock
async def test_hibp_provider_parses_breaches_without_storing_aliases():
    respx.get(url__startswith="https://haveibeenpwned.com/api/v3/breacheddomain/").mock(
        return_value=httpx.Response(200, json={
            "alias1": ["LinkedIn", "Dropbox"], "alias2": ["LinkedIn"],
        }))
    summary = await HibpProvider(api_key="k").domain_breaches("cliente.cl")
    assert summary.account_count == 2
    assert summary.breach_names == ("Dropbox", "LinkedIn")  # deduplicado y ordenado


@respx.mock
async def test_hibp_404_means_no_accounts():
    respx.get(url__startswith="https://haveibeenpwned.com/").mock(return_value=httpx.Response(404))
    summary = await HibpProvider(api_key="k").domain_breaches("cliente.cl")
    assert summary.account_count == 0


def _ids(results) -> set[str]:
    return {r.id.split("@")[0] for r in results}


# -- resolución del proveedor (gating por env) ------------------------------


def test_provider_is_none_without_api_key():
    assert resolve_provider(env={}) is None


def test_provider_configured_with_api_key():
    assert isinstance(resolve_provider(env={"IDATA_HIBP_API_KEY": "k"}), HibpProvider)


# -- el check no corre sin proveedor ----------------------------------------


async def test_check_is_noop_without_provider(make_ctx, monkeypatch):
    monkeypatch.delenv("IDATA_HIBP_API_KEY", raising=False)
    assert await BreachExposureCheck().run(make_ctx()) == []


# -- con proveedor inyectado ------------------------------------------------


class _FakeProvider:
    def __init__(self, summary):
        self._summary = summary

    async def domain_breaches(self, domain):
        return self._summary


async def test_breached_accounts_are_reported_without_leaking_emails(make_ctx):
    provider = _FakeProvider(BreachSummary(account_count=14, breach_names=("LinkedIn", "Dropbox")))
    ctx = make_ctx(target="https://cliente.cl")
    ctx.host = "cliente.cl"

    finding = next(r for r in await BreachExposureCheck(provider).run(ctx)
                   if r.id.startswith("breached_accounts_exposed"))
    assert finding.severity == "high"
    assert "14" in finding.finding and "LinkedIn" in finding.finding
    # Nunca correos concretos: solo conteo y nombres públicos de brechas.
    assert "@cliente.cl" not in finding.evidence


async def test_no_breaches_is_a_pass(make_ctx):
    provider = _FakeProvider(BreachSummary(0, ()))
    assert "breach_none_found" in _ids(await BreachExposureCheck(provider).run(make_ctx()))


async def test_provider_failure_is_not_evaluable(make_ctx):
    class _Boom:
        async def domain_breaches(self, domain):
            raise RuntimeError("HIBP 503")

    results = await BreachExposureCheck(_Boom()).run(make_ctx())
    assert "breach_lookup_unavailable" in _ids(results)
    assert all(r.confidence == "unverified" for r in results)
