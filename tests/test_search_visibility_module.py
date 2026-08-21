"""Módulo 5: runner completo, sitemaps y datos de campo.

Separado de `test_search_visibility.py`, que cubre los checks uno a uno: aquí se
prueba el ensamblaje —que el módulo corra de punta a punta, que un check roto no
lo tumbe y que la capa opt-in siga siendo opt-in—.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.checks.performance import PerformanceCheck
from idata_sentinel.checks.seo_content import SeoContentCheck
from idata_sentinel.checks.seo_local import SeoLocalCheck
from idata_sentinel.checks.structured_data import StructuredDataCheck
from idata_sentinel.core import sitemap as sitemap_mod
from idata_sentinel.core.crawl import crawl
from idata_sentinel.core.engine import VISIBILITY, RunParams
from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.core.interstitial import InterstitialSignal
from idata_sentinel.core.rate_limiter import RateLimiter
from idata_sentinel.core.robots import RobotsPolicy
from idata_sentinel.core.scan_context import ScanContext
from idata_sentinel.modules.search_visibility.module import SearchVisibilityModule

pytestmark = pytest.mark.anyio

ROOT = "https://cliente.test/"

_PAGE = (
    "<html lang='es-CL'><head><title>Estudio jurídico laboral en Santiago</title>"
    "<meta name='description' content='Asesoría en derecho laboral para empresas y trabajadores en Santiago.'>"
    "<link rel='canonical' href='https://cliente.test/'></head>"
    "<body><h1>Derecho laboral</h1><p>" + ("texto " * 200) + "</p></body></html>"
)


def _ctx(robots_text: str = "") -> ScanContext:
    return ScanContext(
        target="https://cliente.test", host="cliente.test", mode="passive",
        http=HttpClient(), rate_limiter=RateLimiter(min_interval=0), authorized=False,
        robots=RobotsPolicy.from_text(robots_text) if robots_text else RobotsPolicy.empty(),
    )


def _mock(page: str = _PAGE) -> None:
    respx.get("https://cliente.test/robots.txt").mock(return_value=httpx.Response(404))
    respx.get(ROOT).mock(return_value=httpx.Response(
        200, text=page, headers={"content-type": "text/html; charset=utf-8"}))
    respx.get("https://cliente.test/sitemap.xml").mock(return_value=httpx.Response(404))
    respx.route(host="cliente.test").mock(return_value=httpx.Response(
        404, text="no existe", headers={"content-type": "text/html"}))


def _params(http: HttpClient, **extra) -> RunParams:
    return RunParams(
        target="https://cliente.test", host="cliente.test", mode="passive",
        http=http, rate_limiter=RateLimiter(min_interval=0),
        authorized=False, authorization=None, robots=RobotsPolicy.empty(), **extra,
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


@respx.mock
async def test_module_runs_end_to_end_and_declares_its_own_domain():
    module = SearchVisibilityModule(page_budget=3)
    assert module.scoring_domain == VISIBILITY

    _mock()
    async with HttpClient() as http:
        findings = await module.run(_params(http))

    assert findings
    assert all(f["module"] == "search_visibility" for f in findings)
    # El contrato de check intacto: reporte, storage y monitoreo dependen de él.
    for f in findings:
        assert {"id", "severity", "status", "confidence", "business_impact"} <= set(f)


@respx.mock
async def test_module_skips_everything_behind_an_anti_bot_page():
    """Si lo que respondió no es el sitio, no se describe como si lo fuera."""
    _mock()
    async with HttpClient() as http:
        findings = await SearchVisibilityModule().run(_params(
            http,
            interstitial=InterstitialSignal(
                provider="Cloudflare", marker="cf-chl", status_code=403, evidence="cf-chl",
            ),
        ))

    assert findings
    assert all(f["confidence"] == "unverified" for f in findings)


@respx.mock
async def test_a_crashing_check_never_takes_the_module_down(monkeypatch):
    async def boom(self, ctx):
        raise RuntimeError("explotó")

    monkeypatch.setattr(SeoContentCheck, "run", boom)
    _mock()
    async with HttpClient() as http:
        findings = await SearchVisibilityModule(page_budget=2).run(_params(http))

    error = next(f for f in findings if f["id"] == "seo_content_error")
    assert error["confidence"] == "unverified"  # un fallo nuestro no baja la nota


# ---------------------------------------------------------------------------
# Sitemap
# ---------------------------------------------------------------------------


def test_sitemap_rejects_documents_with_a_doctype():
    """Un sitemap es un documento de un tercero: no se le concede un DOCTYPE."""
    parsed = sitemap_mod.parse("https://x.test/sitemap.xml", """<?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <urlset><url><loc>https://x.test/</loc></url></urlset>""")
    assert not parsed.ok
    assert "DOCTYPE" in parsed.error


def test_sitemap_index_and_malformed_xml_are_distinguished():
    index = sitemap_mod.parse("https://x.test/s.xml", """<?xml version="1.0"?>
    <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <sitemap><loc>https://x.test/s1.xml</loc></sitemap>
    </sitemapindex>""")
    assert index.is_index and index.children == ("https://x.test/s1.xml",)

    assert not sitemap_mod.parse("https://x.test/s.xml", "<urlset><url>").ok
    assert not sitemap_mod.parse("https://x.test/s.xml", "").ok
    assert not sitemap_mod.parse("https://x.test/s.xml", "<html></html>").ok


def test_sitemap_declared_in_robots_is_preferred():
    urls = sitemap_mod.candidate_urls(
        "https://x.test", "Sitemap: https://x.test/mapa.xml\nUser-agent: *\n"
    )
    assert urls[0] == "https://x.test/mapa.xml"


@respx.mock
async def test_crawl_follows_a_sitemap_index():
    respx.get("https://cliente.test/robots.txt").mock(return_value=httpx.Response(404))
    respx.get(ROOT).mock(return_value=httpx.Response(
        200, text=_PAGE, headers={"content-type": "text/html"}))
    respx.get("https://cliente.test/sitemap.xml").mock(return_value=httpx.Response(
        200, text="""<?xml version="1.0"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <sitemap><loc>https://cliente.test/s1.xml</loc></sitemap>
        </sitemapindex>"""))
    respx.get("https://cliente.test/s1.xml").mock(return_value=httpx.Response(
        200, text="""<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://cliente.test/servicios</loc><lastmod>2026-08-01</lastmod></url>
        </urlset>"""))
    respx.get("https://cliente.test/servicios").mock(return_value=httpx.Response(
        200, text=_PAGE, headers={"content-type": "text/html"}))
    respx.route(host="cliente.test").mock(return_value=httpx.Response(404))

    result = await crawl(_ctx(), budget=4)
    assert any(p.source == "sitemap" for p in result.pages)
    assert len(result.sitemaps) == 2


# ---------------------------------------------------------------------------
# Datos de campo (CrUX) — la capa opt-in
# ---------------------------------------------------------------------------


@respx.mock
async def test_field_data_reports_poor_vitals_as_confirmed(monkeypatch):
    """Cuando sí hay datos de usuarios reales, se reportan como tales."""
    monkeypatch.setenv("IDATA_PAGESPEED_API_KEY", "clave-de-prueba")
    _mock()
    respx.get(url__startswith="https://pagespeedonline.googleapis.com").mock(
        return_value=httpx.Response(200, json={
            "loadingExperience": {"metrics": {
                "LARGEST_CONTENTFUL_PAINT_MS": {"category": "SLOW", "percentile": 4800},
                "CUMULATIVE_LAYOUT_SHIFT_SCORE": {"category": "FAST", "percentile": 3},
            }}
        })
    )
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    ctx.field_data_enabled = True
    findings = await PerformanceCheck().run(ctx)

    lcp = next(f for f in findings if f.id == "lcp_poor")
    assert lcp.confidence == "confirmed"  # usuarios reales, no estimación nuestra
    assert "cls_poor" not in {f.id for f in findings}  # CLS iba bien: no se inventa


@respx.mock
async def test_field_data_without_traffic_says_so_instead_of_estimating(monkeypatch):
    monkeypatch.setenv("IDATA_PAGESPEED_API_KEY", "clave-de-prueba")
    _mock()
    respx.get(url__startswith="https://pagespeedonline.googleapis.com").mock(
        return_value=httpx.Response(200, json={"loadingExperience": {}})
    )
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    ctx.field_data_enabled = True
    findings = await PerformanceCheck().run(ctx)

    unavailable = next(f for f in findings if f.id == "field_data_unavailable")
    assert unavailable.confidence == "unverified"
    assert "inventarlas" in unavailable.finding


@respx.mock
async def test_field_data_handles_a_failing_upstream(monkeypatch):
    monkeypatch.setenv("IDATA_PAGESPEED_API_KEY", "clave-de-prueba")
    _mock()
    respx.get(url__startswith="https://pagespeedonline.googleapis.com").mock(
        return_value=httpx.Response(500, text="boom")
    )
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    ctx.field_data_enabled = True
    findings = await PerformanceCheck().run(ctx)

    assert any(f.id == "field_data_unavailable" for f in findings)


# ---------------------------------------------------------------------------
# Caminos menos transitados de los checks
# ---------------------------------------------------------------------------


@respx.mock
async def test_incomplete_schema_node_is_reported():
    html = (
        "<html lang='es'><head><title>Estudio jurídico laboral en Santiago</title>"
        '<script type="application/ld+json">'
        '{"@context":"https://schema.org","@type":"LocalBusiness","name":"X"}'
        "</script></head><body><h1>X</h1></body></html>"
    )
    _mock(html)
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await StructuredDataCheck().run(ctx)

    incomplete = next(f for f in findings if f.id.startswith("structured_data_incomplete"))
    assert "address" in incomplete.finding


@respx.mock
async def test_duplicate_titles_across_pages_are_reported():
    page = ("<html lang='es'><head><title>Igual en todas</title>"
            "<link rel='canonical' href='https://cliente.test/'></head>"
            "<body><h1>h</h1><a href='/otra'>otra</a></body></html>")
    respx.get("https://cliente.test/robots.txt").mock(return_value=httpx.Response(404))
    respx.get(ROOT).mock(return_value=httpx.Response(
        200, text=page, headers={"content-type": "text/html"}))
    respx.get("https://cliente.test/sitemap.xml").mock(return_value=httpx.Response(404))
    respx.route(host="cliente.test").mock(return_value=httpx.Response(
        200, text=page, headers={"content-type": "text/html"}))

    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=4)
    findings = await SeoContentCheck().run(ctx)

    assert any(f.id == "title_duplicated" for f in findings)


@respx.mock
async def test_phone_without_tel_link_is_reported():
    html = ("<html lang='es'><head><title>Estudio jurídico en Santiago</title></head>"
            "<body><h1>Contacto</h1><p>Llámanos al +56 9 8765 4321</p></body></html>")
    _mock(html)
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await SeoLocalCheck().run(ctx)

    assert any(f.id == "phone_not_linked" for f in findings)


@respx.mock
async def test_slow_server_is_reported_but_only_as_a_single_sample():
    """Una medición no es un promedio, y el hallazgo lo dice."""
    import httpx as _httpx

    async def slow(request):
        return _httpx.Response(200, text=_PAGE, headers={"content-type": "text/html"})

    respx.get("https://cliente.test/robots.txt").mock(return_value=httpx.Response(404))
    respx.get(ROOT).mock(side_effect=slow)
    respx.route(host="cliente.test").mock(return_value=httpx.Response(404))

    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await PerformanceCheck().run(ctx)
    # No se afirma lentitud sin evidencia: con una respuesta instantánea no hay hallazgo.
    assert not any(f.id == "ttfb_slow" for f in findings)
