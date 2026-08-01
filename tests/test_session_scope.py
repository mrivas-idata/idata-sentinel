"""Escaneo autenticado con sesión provista: scope, no-fuga y solo-lectura
(plan activo §7). La sesión es material sensible del cliente: nunca sale de su
scope, nunca aparece en evidencia/log, y nunca acompaña a un método de escritura.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.core.session import ClientSession


def _session() -> ClientSession:
    return ClientSession(kind="cookie", material="sid=SECRETO", scope_hosts=frozenset({"example.test"}))


# -- adjunta la sesión solo dentro del scope --------------------------------


@respx.mock
async def test_session_attached_to_in_scope_authenticated_request(make_ctx):
    route = respx.get("https://example.test/panel").mock(return_value=httpx.Response(200, text="ok"))
    ctx = make_ctx(mode="audit", authorized=True)
    ctx.client_session = _session()

    await ctx.get_outcome("/panel", authenticated=True)

    sent = route.calls[0].request.headers.get("cookie")
    assert sent == "sid=SECRETO"


@respx.mock
async def test_session_not_attached_when_not_requested(make_ctx):
    """Sin `authenticated=True`, la petición va anónima aunque haya sesión."""
    route = respx.get("https://example.test/panel").mock(return_value=httpx.Response(200, text="ok"))
    ctx = make_ctx(mode="audit", authorized=True)
    ctx.client_session = _session()

    await ctx.get_outcome("/panel", authenticated=False)
    assert "cookie" not in {k.lower() for k in route.calls[0].request.headers}


@respx.mock
async def test_session_never_sent_off_scope(make_ctx):
    """El host objetivo fuera del scope de la sesión: no se adjunta."""
    route = respx.get("https://otro.test/x").mock(return_value=httpx.Response(200, text="ok"))
    ctx = make_ctx(target="https://otro.test", mode="audit", authorized=True)
    ctx.host = "otro.test"
    ctx.client_session = _session()  # scope solo example.test

    await ctx.get_outcome("https://otro.test/x", authenticated=True)
    assert "cookie" not in {k.lower() for k in route.calls[0].request.headers}


# -- no-fuga ----------------------------------------------------------------

def test_session_material_absent_from_repr():
    assert "SECRETO" not in repr(_session())


# -- solo lectura (garantía estructural del cliente HTTP) -------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_http_client_refuses_write_methods(method):
    """El escáner no puede mutar estado en el objetivo, ni siquiera con sesión."""
    async with HttpClient() as http:
        with pytest.raises(ValueError, match="solo lectura"):
            await http.request("https://example.test/", method=method)


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
@respx.mock
async def test_http_client_allows_read_methods(method):
    respx.route(method=method, url="https://example.test/").mock(return_value=httpx.Response(200))
    async with HttpClient() as http:
        outcome = await http.request("https://example.test/", method=method)
    assert outcome.ok
