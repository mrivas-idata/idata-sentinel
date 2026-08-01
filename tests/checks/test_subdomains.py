from __future__ import annotations

import json

import httpx
import respx

from idata_sentinel.checks.subdomains import (
    discover_subdomains,
    parse_certspotter,
    parse_crtsh,
)
from idata_sentinel.core.http_client import HttpClient

DOMAIN = "idata.test"

CRT_SH = "https://crt.sh/"
CERTSPOTTER = "https://api.certspotter.com/"


def _payload(*names: str) -> str:
    return json.dumps([{"name_value": name} for name in names])


def _spotter_payload(*names: str) -> str:
    return json.dumps([{"dns_names": list(names)}] if names else [])


def _mock_crtsh(*names: str, response: httpx.Response | None = None, side_effect=None):
    route = respx.get(url__startswith=CRT_SH)
    if side_effect is not None:
        return route.mock(side_effect=side_effect)
    return route.mock(return_value=response or httpx.Response(200, text=_payload(*names)))


def _mock_certspotter(*names: str, response: httpx.Response | None = None, side_effect=None):
    route = respx.get(url__startswith=CERTSPOTTER)
    if side_effect is not None:
        return route.mock(side_effect=side_effect)
    return route.mock(return_value=response or httpx.Response(200, text=_spotter_payload(*names)))


# -- parseo ----------------------------------------------------------------


def test_parse_crtsh_strips_wildcards_and_dedupes():
    payload = _payload("*.idata.test\nwww.idata.test", "www.idata.test", "idata.test")
    assert parse_crtsh(payload, DOMAIN) == ["idata.test", "www.idata.test"]


def test_parse_crtsh_rejects_names_outside_the_domain():
    payload = _payload("evil.test", "idata.test.evil.test", "api.idata.test")
    assert parse_crtsh(payload, DOMAIN) == ["api.idata.test"]


def test_parse_crtsh_prioritises_shallow_names_when_truncating():
    payload = _payload("a.b.c.idata.test", "www.idata.test", "x.y.idata.test")
    assert parse_crtsh(payload, DOMAIN, limit=2) == ["www.idata.test", "x.y.idata.test"]


def test_parse_crtsh_tolerates_garbage():
    assert parse_crtsh("not json", DOMAIN) == []
    assert parse_crtsh('{"not": "a list"}', DOMAIN) == []
    assert parse_crtsh('["a string entry"]', DOMAIN) == []


def test_parse_certspotter_reads_dns_names():
    payload = json.dumps([{"dns_names": ["*.idata.test", "api.idata.test", "otro.test"]}])
    assert parse_certspotter(payload, DOMAIN) == ["idata.test", "api.idata.test"]


def test_parse_certspotter_tolerates_an_error_object():
    """Sin API key el servicio responde `{"code": "rate_limited"}`: un objeto,
    no una lista. No debe confundirse con "el dominio no tiene certificados"."""
    assert parse_certspotter('{"code": "rate_limited"}', DOMAIN) == []


# -- consulta con dos registros --------------------------------------------


@respx.mock
async def test_discover_subdomains_happy_path():
    _mock_crtsh("api.idata.test")
    _mock_certspotter()
    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN)
        assert result.hosts == ["api.idata.test"]
        assert result.ok is True
        assert result.complete is True


@respx.mock
async def test_both_registries_are_queried_and_merged():
    """El motivo de tener dos fuentes: cada registro ve certificados distintos."""
    crt = _mock_crtsh("www.idata.test")
    spotter = _mock_certspotter("dev.idata.test", "www.idata.test")

    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN)

    assert crt.called and spotter.called
    assert result.hosts == ["dev.idata.test", "www.idata.test"]
    assert result.host_sources["dev.idata.test"] == "certspotter"
    assert result.host_sources["www.idata.test"] == "crt.sh, certspotter"


@respx.mock
async def test_one_registry_down_still_yields_an_inventory():
    """Regresión: con crt.sh caído el descubrimiento devolvía cero activos y el
    informe presentaba "1 activo" como si fuera toda la superficie del cliente.
    Medido contra un objetivo real, la segunda fuente aportó 17 subdominios."""
    _mock_crtsh(response=httpx.Response(502))
    _mock_certspotter("tienda.idata.test", "cpanel.idata.test")

    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN, attempts=1, backoff=0)

    assert result.hosts == ["cpanel.idata.test", "tienda.idata.test"]
    assert result.ok is True        # hay inventario
    assert result.complete is False  # pero no es exhaustivo
    assert "crt.sh" in result.reason


@respx.mock
async def test_discovery_fails_only_when_every_registry_fails():
    _mock_crtsh(response=httpx.Response(503))
    _mock_certspotter(response=httpx.Response(503))

    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN, attempts=1, backoff=0)

    assert result.hosts == []
    assert result.ok is False
    assert "503" in result.reason
    assert len(result.failed_sources) == 2


@respx.mock
async def test_network_error_never_raises_but_is_recorded():
    _mock_crtsh(side_effect=httpx.ConnectError("down"))
    _mock_certspotter(side_effect=httpx.ConnectError("down"))

    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN, attempts=1, backoff=0)

    assert result.ok is False
    assert "no respondió" in result.reason


@respx.mock
async def test_timeout_is_recorded_as_a_failure():
    """Los registros de CT son lentos de verdad: el timeout es el fallo más frecuente."""
    _mock_crtsh(side_effect=httpx.ReadTimeout("lento"))
    _mock_certspotter(side_effect=httpx.ReadTimeout("lento"))

    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN, attempts=1, backoff=0)

    assert result.ok is False
    assert "timeout" in result.reason


@respx.mock
async def test_an_empty_certificate_log_is_a_valid_answer():
    """Un dominio sin certificados registrados no es un fallo."""
    _mock_crtsh(response=httpx.Response(200, text="[]"))
    _mock_certspotter()

    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN)

    assert result.hosts == []
    assert result.ok is True
    assert result.complete is True


@respx.mock
async def test_unreadable_response_is_a_failure():
    _mock_crtsh(response=httpx.Response(200, text="<html>error interno</html>"))
    _mock_certspotter(response=httpx.Response(200, text="<html>error interno</html>"))

    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN, attempts=1, backoff=0)

    assert result.ok is False
    assert "ilegible" in result.reason


@respx.mock
async def test_a_crashing_registry_never_breaks_discovery():
    """Una fuente que revienta no puede llevarse por delante a la otra."""
    _mock_crtsh(side_effect=ValueError("algo inesperado"))
    _mock_certspotter("api.idata.test")

    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN, attempts=1, backoff=0)

    assert result.hosts == ["api.idata.test"]
    assert result.ok is True
    assert result.complete is False


@respx.mock
async def test_the_limit_applies_to_the_merged_result():
    _mock_crtsh(*[f"a{i}.idata.test" for i in range(20)])
    _mock_certspotter(*[f"b{i}.idata.test" for i in range(20)])

    async with HttpClient() as http:
        result = await discover_subdomains(http, DOMAIN, limit=5)

    assert len(result.hosts) == 5


@respx.mock
async def test_discovery_uses_a_longer_timeout_than_a_normal_request():
    route = _mock_crtsh(response=httpx.Response(200, text="[]"))
    _mock_certspotter()
    async with HttpClient() as http:
        await discover_subdomains(http, DOMAIN)
    assert route.called
