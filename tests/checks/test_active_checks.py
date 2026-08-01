"""Checks de configuración activos (plan activo §6). Todos: solo audit, exigen
habilitación por nombre, solo métodos de lectura, y separan diagnóstico de ataque.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.checks.auth_enforcement import AuthEnforcementCheck
from idata_sentinel.checks.cors_config import PROBE_ORIGIN, CorsConfigCheck
from idata_sentinel.checks.http_methods import HttpMethodsCheck
from idata_sentinel.checks.redirect_audit import RedirectAuditCheck

ROOT = "https://example.test/"


def _ids(results) -> set[str]:
    return {r.id.split("@")[0] for r in results}


def _active_ctx(make_ctx, check_id: str, **kw):
    """Contexto audit con el check activo habilitado por nombre + confirmación."""
    ctx = make_ctx(mode="audit", authorized=True, **kw)
    ctx.active_checks = frozenset({check_id})
    ctx.active_acknowledged = True
    return ctx


# -- guardas de activación (comunes a todos) --------------------------------


@pytest.mark.parametrize("check_cls,cid", [
    (HttpMethodsCheck, "http_methods"),
    (CorsConfigCheck, "cors_config"),
    (AuthEnforcementCheck, "auth_enforcement"),
    (RedirectAuditCheck, "redirect_audit"),
])
@respx.mock
async def test_active_check_is_silent_without_activation(check_cls, cid, make_ctx):
    respx.get(url__regex=r"https://example\.test.*").mock(return_value=httpx.Response(200, text="x"))
    # Modo audit autorizado pero SIN nombrar el check ni confirmar: silencio total.
    ctx = make_ctx(mode="audit", authorized=True, audit_endpoints=("/api/privado",))
    assert await check_cls().run(ctx) == []


# -- http_methods -----------------------------------------------------------


@respx.mock
async def test_http_methods_flags_trace(make_ctx):
    respx.route(method="OPTIONS", url=ROOT).mock(
        return_value=httpx.Response(200, headers={"Allow": "GET, POST, OPTIONS, TRACE"}))
    results = await HttpMethodsCheck().run(_active_ctx(make_ctx, "http_methods"))
    assert "http_trace_enabled" in _ids(results)


@respx.mock
async def test_http_methods_options_unsupported_is_not_a_finding(make_ctx):
    respx.route(method="OPTIONS", url=ROOT).mock(return_value=httpx.Response(405))
    results = await HttpMethodsCheck().run(_active_ctx(make_ctx, "http_methods"))
    assert "http_methods_not_supported" in _ids(results)
    assert not any(r.status in ("fail", "warning") for r in results)


@respx.mock
async def test_http_methods_flags_write_methods(make_ctx):
    respx.route(method="OPTIONS", url=ROOT).mock(
        return_value=httpx.Response(200, headers={"Allow": "GET, PUT, DELETE"}))
    results = await HttpMethodsCheck().run(_active_ctx(make_ctx, "http_methods"))
    assert "http_write_methods_advertised" in _ids(results)


@respx.mock
async def test_http_methods_unreachable_is_not_a_finding(make_ctx):
    respx.route(method="OPTIONS", url=ROOT).mock(side_effect=httpx.ConnectError("caído"))
    results = await HttpMethodsCheck().run(_active_ctx(make_ctx, "http_methods"))
    assert "http_methods_unreachable" in _ids(results)
    assert all(r.confidence == "unverified" for r in results)


@respx.mock
async def test_http_methods_baseline_mismatch(make_ctx):
    from idata_sentinel.core.baseline import HardeningBaseline
    respx.route(method="OPTIONS", url=ROOT).mock(
        return_value=httpx.Response(200, headers={"Allow": "GET, POST, DELETE"}))
    ctx = _active_ctx(make_ctx, "http_methods")
    ctx._compiled_baseline = HardeningBaseline.load({
        "version": 1,
        "paths": {"/": {"methods": {"allowed": ["GET", "POST"], "severity": "high"}}},
    })
    results = await HttpMethodsCheck().run(ctx)
    m = next(r for r in results if r.id.startswith("methods_baseline_mismatch"))
    assert m.severity == "high" and m.confidence == "confirmed"


@respx.mock
async def test_http_methods_only_emits_options(make_ctx):
    """Anti-ataque: el check NUNCA invoca los métodos peligrosos, solo pregunta."""
    route = respx.route(method="OPTIONS", url=ROOT).mock(
        return_value=httpx.Response(200, headers={"Allow": "GET, PUT, DELETE"}))
    await HttpMethodsCheck().run(_active_ctx(make_ctx, "http_methods"))
    assert route.called
    assert all(call.request.method == "OPTIONS" for call in route.calls)


# -- cors_config ------------------------------------------------------------


@respx.mock
async def test_cors_reflects_arbitrary_origin_with_credentials(make_ctx):
    respx.get(ROOT).mock(return_value=httpx.Response(
        200, headers={"access-control-allow-origin": PROBE_ORIGIN,
                      "access-control-allow-credentials": "true"}, text="x"))
    results = await CorsConfigCheck().run(_active_ctx(make_ctx, "cors_config"))
    finding = next(r for r in results if r.id.startswith("cors_reflects_arbitrary_origin"))
    assert finding.severity == "high"


@respx.mock
async def test_cors_wildcard_is_flagged_medium(make_ctx):
    respx.get(ROOT).mock(return_value=httpx.Response(
        200, headers={"access-control-allow-origin": "*"}, text="x"))
    results = await CorsConfigCheck().run(_active_ctx(make_ctx, "cors_config"))
    assert "cors_wildcard_origin" in _ids(results)


@respx.mock
async def test_cors_null_origin_is_flagged(make_ctx):
    respx.get(ROOT).mock(return_value=httpx.Response(
        200, headers={"access-control-allow-origin": "null"}, text="x"))
    results = await CorsConfigCheck().run(_active_ctx(make_ctx, "cors_config"))
    assert "cors_null_origin_allowed" in _ids(results)


@respx.mock
async def test_cors_without_cors_headers_is_silent(make_ctx):
    respx.get(ROOT).mock(return_value=httpx.Response(200, text="x"))
    assert await CorsConfigCheck().run(_active_ctx(make_ctx, "cors_config")) == []


@respx.mock
async def test_cors_sends_exactly_one_probe_per_endpoint(make_ctx):
    """Anti-fuzzing: una sola sonda, con un Origin fijo. No se enumeran orígenes."""
    route = respx.get(ROOT).mock(return_value=httpx.Response(200, text="x"))
    await CorsConfigCheck().run(_active_ctx(make_ctx, "cors_config"))
    assert route.call_count == 1
    assert route.calls[0].request.headers.get("origin") == PROBE_ORIGIN


# -- auth_enforcement -------------------------------------------------------


@respx.mock
async def test_auth_enforcement_flags_open_sensitive_endpoint(make_ctx):
    respx.get("https://example.test/api/privado").mock(
        return_value=httpx.Response(200, json={"secreto": "expuesto"}))
    ctx = _active_ctx(make_ctx, "auth_enforcement", audit_endpoints=("/api/privado",))
    results = await AuthEnforcementCheck().run(ctx)
    finding = next(r for r in results if r.id.startswith("sensitive_endpoint_no_auth"))
    assert finding.severity == "high"


@respx.mock
async def test_auth_enforcement_accepts_a_closed_endpoint(make_ctx):
    respx.get("https://example.test/api/privado").mock(return_value=httpx.Response(401))
    ctx = _active_ctx(make_ctx, "auth_enforcement", audit_endpoints=("/api/privado",))
    results = await AuthEnforcementCheck().run(ctx)
    assert "sensitive_endpoint_auth_ok" in _ids(results)


@respx.mock
async def test_auth_enforcement_spa_shell_is_not_a_false_positive(make_ctx):
    """Un SPA que responde 200 con index.html a rutas desconocidas NO es un fallo."""
    respx.get("https://example.test/api/privado").mock(
        return_value=httpx.Response(200, text="<!DOCTYPE html><html><body>app</body></html>"))
    ctx = _active_ctx(make_ctx, "auth_enforcement", audit_endpoints=("/api/privado",))
    results = await AuthEnforcementCheck().run(ctx)
    assert "sensitive_endpoint_no_auth" not in _ids(results)


@respx.mock
async def test_auth_enforcement_uses_anonymous_requests(make_ctx):
    """Anti-ataque: verifica el cierre SIN credenciales; nunca las prueba."""
    route = respx.get("https://example.test/api/privado").mock(return_value=httpx.Response(401))
    ctx = _active_ctx(make_ctx, "auth_enforcement", audit_endpoints=("/api/privado",))
    await AuthEnforcementCheck().run(ctx)
    assert "authorization" not in {k.lower() for k in route.calls[0].request.headers}
    assert "cookie" not in {k.lower() for k in route.calls[0].request.headers}


# -- redirect_audit ---------------------------------------------------------


@respx.mock
async def test_redirect_audit_flags_https_downgrade(make_ctx):
    respx.get(ROOT).mock(return_value=httpx.Response(302, headers={"location": "http://example.test/x"}))
    respx.get("http://example.test/x").mock(return_value=httpx.Response(200, text="fin"))  # 2º salto
    results = await RedirectAuditCheck().run(_active_ctx(make_ctx, "redirect_audit"))
    assert "redirect_downgrade_https" in _ids(results)


@respx.mock
async def test_redirect_audit_flags_offscope_host(make_ctx):
    respx.get(ROOT).mock(return_value=httpx.Response(302, headers={"location": "https://otro-dominio.com/x"}))
    results = await RedirectAuditCheck().run(_active_ctx(make_ctx, "redirect_audit"))
    assert "redirect_offscope_host" in _ids(results)


@respx.mock
async def test_redirect_audit_silent_on_clean_endpoint(make_ctx):
    respx.get(ROOT).mock(return_value=httpx.Response(200, text="ok"))
    results = await RedirectAuditCheck().run(_active_ctx(make_ctx, "redirect_audit"))
    assert results == []
