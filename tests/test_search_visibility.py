"""Módulo 5 — visibilidad en buscadores y motores generativos.

El primer test del archivo es el que protege la decisión de arquitectura del
plan: los dos ejes se puntúan por separado. Si alguna vez se rompe, el informe
empieza a mezclar riesgo de seguridad con SEO y deja de significar nada.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from idata_sentinel.core.crawl import DEFAULT_PAGE_BUDGET, crawl
from idata_sentinel.core.engine import SECURITY, VISIBILITY
from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.core.rate_limiter import RateLimiter
from idata_sentinel.core.robots import RobotsPolicy
from idata_sentinel.core.scan_context import ScanContext
from idata_sentinel.checks.geo_readiness import GeoReadinessCheck
from idata_sentinel.checks.performance import PerformanceCheck
from idata_sentinel.checks.seo_content import SeoContentCheck
from idata_sentinel.checks.seo_indexability import SeoIndexabilityCheck
from idata_sentinel.checks.seo_local import SeoLocalCheck
from idata_sentinel.checks.structured_data import StructuredDataCheck
from idata_sentinel.scoring.risk_engine import calculate, modules_for_domain

pytestmark = pytest.mark.anyio

ROOT = "https://cliente.test/"

_FULL_PAGE = """<!doctype html>
<html lang="es-CL">
<head>
  <title>Abogados Ejemplo | Derecho laboral en Santiago</title>
  <meta name="description" content="Estudio jurídico especializado en derecho laboral, con atención en Santiago y regiones desde 2009.">
  <link rel="canonical" href="https://cliente.test/">
  <meta property="og:title" content="Abogados Ejemplo">
  <meta property="og:description" content="Derecho laboral">
  <meta property="og:image" content="https://cliente.test/og.png">
  <script type="application/ld+json">
  {"@context":"https://schema.org","@type":"ProfessionalService","name":"Abogados Ejemplo",
   "url":"https://cliente.test/","telephone":"+56912345678",
   "address":{"@type":"PostalAddress","streetAddress":"Av. Siempre Viva 123"},
   "openingHours":"Mo-Fr 09:00-18:00","areaServed":"Santiago",
   "sameAs":["https://www.linkedin.com/company/ejemplo"],
   "author":{"@type":"Person","name":"Ana Pérez"},"datePublished":"2026-01-15"}
  </script>
</head>
<body>
  <h1>Abogados especialistas en derecho laboral</h1>
  <h2>¿Cuánto demora un juicio laboral?</h2>
  <p>%s</p>
  <ul><li>Despido injustificado</li><li>Tutela de derechos</li></ul>
  <img src="/foto.jpg" alt="Equipo" width="800" height="600" loading="lazy">
  <a href="tel:+56912345678">+56 9 1234 5678</a>
  <a href="/servicios">Servicios</a>
</body></html>""" % ("palabra " * 200)


def _ctx(*, robots_text: str = "") -> ScanContext:
    return ScanContext(
        target="https://cliente.test",
        host="cliente.test",
        mode="passive",
        http=HttpClient(),
        rate_limiter=RateLimiter(min_interval=0),
        authorized=False,
        robots=RobotsPolicy.from_text(robots_text) if robots_text else RobotsPolicy.empty(),
    )


def _mock(page_html: str = _FULL_PAGE, *, robots: str = "", sitemap: str | None = None) -> None:
    respx.get("https://cliente.test/robots.txt").mock(
        return_value=httpx.Response(200 if robots else 404, text=robots)
    )
    respx.get(ROOT).mock(return_value=httpx.Response(
        200, text=page_html, headers={"content-type": "text/html; charset=utf-8"}
    ))
    respx.get("https://cliente.test/sitemap.xml").mock(
        return_value=httpx.Response(200, text=sitemap) if sitemap else httpx.Response(404)
    )
    respx.route(host="cliente.test").mock(
        return_value=httpx.Response(404, text="no existe", headers={"content-type": "text/html"})
    )


# ---------------------------------------------------------------------------
# La decisión de arquitectura del plan (§2)
# ---------------------------------------------------------------------------


def _finding(fid: str, module: str, severity: str = "critical") -> dict:
    return {
        "id": fid, "module": module, "category": "x", "severity": severity,
        "likelihood": "high", "status": "fail", "confidence": "high",
        "verification_status": "unverified", "title": fid, "finding": "f",
        "business_impact": "b", "recommendation": "r", "evidence": "e", "references": [],
    }


def test_visibility_findings_never_touch_the_security_score():
    """El aislamiento de ejes, que es lo que sostiene todo el módulo.

    Sin esto, un sitio con un RCE sin parche mejoraría su nota de seguridad por
    tener buenos títulos, y un sitio bien asegurado reprobaría por no publicar
    sitemap. Las dos lecturas son falsas.
    """
    scan_result = {
        "modules_by_domain": {
            SECURITY: {"vuln_identification": [_finding("hsts_missing", "vuln_identification", "medium")]},
            VISIBILITY: {"search_visibility": [
                _finding("robots_blocks_indexing", "search_visibility"),
                _finding("meta_robots_noindex", "search_visibility"),
            ]},
        }
    }
    security = calculate(modules_for_domain(scan_result, SECURITY))
    visibility = calculate(modules_for_domain(scan_result, VISIBILITY))

    solo_security = calculate({"vuln_identification": [
        _finding("hsts_missing", "vuln_identification", "medium")
    ]})

    assert security.score == solo_security.score  # dos críticos de SEO: cero efecto
    assert visibility.grade == "F"
    assert security.grade != "F"


def test_a_scan_without_the_module_reports_no_visibility_score():
    """No haber medido no es una nota alta: es ausencia de nota."""
    scan_result = {"modules_by_domain": {SECURITY: {"vuln_identification": []}}}
    assert modules_for_domain(scan_result, VISIBILITY) == {}


# ---------------------------------------------------------------------------
# Presupuesto de rastreo (§5)
# ---------------------------------------------------------------------------


@respx.mock
async def test_crawl_respects_its_page_budget():
    sitemap = """<?xml version="1.0"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://cliente.test/a</loc><lastmod>2026-08-01</lastmod></url>
      <url><loc>https://cliente.test/b</loc><lastmod>2026-07-01</lastmod></url>
      <url><loc>https://cliente.test/c</loc></url>
    </urlset>"""
    _mock(sitemap=sitemap)
    result = await crawl(_ctx(), budget=3)

    assert len(result.pages) <= 3
    assert result.budget == 3


@respx.mock
async def test_crawl_declares_what_it_left_out():
    """Un análisis parcial nunca se presenta como completo."""
    sitemap = """<?xml version="1.0"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://cliente.test/a</loc></url>
      <url><loc>https://cliente.test/b</loc></url>
      <url><loc>https://cliente.test/c</loc></url>
    </urlset>"""
    _mock(sitemap=sitemap)
    result = await crawl(_ctx(), budget=2)

    assert not result.complete
    assert result.skipped

    findings = await SeoIndexabilityCheck().run(_with_crawl(result))
    assert any(f.id == "seo_crawl_incomplete" for f in findings)


def _with_crawl(crawl_result):
    ctx = _ctx()
    ctx.crawl = crawl_result
    return ctx


# ---------------------------------------------------------------------------
# Indexabilidad (§6.1)
# ---------------------------------------------------------------------------


@respx.mock
async def test_robots_blocking_everything_is_critical():
    _mock(robots="User-agent: *\nDisallow: /\n")
    ctx = _ctx(robots_text="User-agent: *\nDisallow: /\n")
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await SeoIndexabilityCheck().run(ctx)

    blocked = next(f for f in findings if f.id == "robots_blocks_indexing")
    assert blocked.severity == "critical"
    assert blocked.status == "fail"


@respx.mock
async def test_noindex_is_critical():
    html = _FULL_PAGE.replace("<title>", '<meta name="robots" content="noindex,follow"><title>')
    _mock(html)
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await SeoIndexabilityCheck().run(ctx)

    noindex = next(f for f in findings if f.id.startswith("meta_robots_noindex"))
    assert noindex.severity == "critical"


@respx.mock
async def test_a_well_formed_page_does_not_produce_indexability_failures():
    """Control negativo: un sitio correcto no debe generar hallazgos inventados."""
    sitemap = """<?xml version="1.0"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://cliente.test/</loc></url>
    </urlset>"""
    _mock(robots="User-agent: *\nAllow: /\nSitemap: https://cliente.test/sitemap.xml\n",
          sitemap=sitemap)
    ctx = _ctx(robots_text="User-agent: *\nAllow: /\n")
    ctx.crawl = await crawl(ctx, budget=3)
    findings = await SeoIndexabilityCheck().run(ctx)

    ids = {f.id for f in findings}
    assert not any(i.startswith(("robots_blocks", "meta_robots_noindex", "canonical_missing")) for i in ids)


@respx.mock
async def test_soft_404_detected_when_missing_pages_return_200():
    respx.get("https://cliente.test/robots.txt").mock(return_value=httpx.Response(404))
    respx.get(ROOT).mock(return_value=httpx.Response(
        200, text=_FULL_PAGE, headers={"content-type": "text/html"}))
    respx.get("https://cliente.test/sitemap.xml").mock(return_value=httpx.Response(404))
    # Cualquier otra ruta —incluida la sonda inexistente— responde 200.
    respx.route(host="cliente.test").mock(return_value=httpx.Response(
        200, text="<html><body>Página no encontrada</body></html>",
        headers={"content-type": "text/html"}))

    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=4)
    findings = await SeoIndexabilityCheck().run(ctx)
    assert any(f.id == "soft_404" for f in findings)


# ---------------------------------------------------------------------------
# Contenido (§6.2)
# ---------------------------------------------------------------------------


@respx.mock
async def test_missing_title_and_h1_are_reported():
    _mock("<html><body><p>hola</p></body></html>")
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await SeoContentCheck().run(ctx)
    ids = {f.id.split("@")[0] for f in findings}

    assert "title_missing" in ids
    assert "h1_missing" in ids
    assert "lang_not_declared" in ids


@respx.mock
async def test_a_complete_page_reports_no_content_failures():
    _mock()
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await SeoContentCheck().run(ctx)

    failures = {f.id.split("@")[0] for f in findings if f.status == "fail"}
    assert "title_missing" not in failures
    assert "h1_missing" not in failures
    assert "meta_description_missing" not in failures


# ---------------------------------------------------------------------------
# GEO (§7)
# ---------------------------------------------------------------------------


@respx.mock
async def test_blocking_citation_agents_is_high_and_training_is_only_informative():
    """La distinción que hace útil el check: no todo bloqueo es un problema."""
    robots = (
        "User-agent: GPTBot\nDisallow: /\n\n"
        "User-agent: PerplexityBot\nDisallow: /\n\n"
        "User-agent: *\nAllow: /\n"
    )
    _mock(robots=robots)
    ctx = _ctx(robots_text=robots)
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await GeoReadinessCheck().run(ctx)
    by_id = {f.id: f for f in findings}

    citation = by_id["ai_crawlers_blocked_from_citation"]
    assert citation.severity == "high"
    assert "PerplexityBot" in citation.finding

    training = by_id["ai_crawlers_blocked_from_training"]
    assert training.severity == "info"
    assert training.status == "info"
    assert "GPTBot" in training.finding


@respx.mock
async def test_no_ai_policy_at_all_is_reported():
    _mock(robots="User-agent: *\nAllow: /\n")
    ctx = _ctx(robots_text="User-agent: *\nAllow: /\n")
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await GeoReadinessCheck().run(ctx)

    assert any(f.id == "ai_crawler_policy_absent" for f in findings)


@respx.mock
async def test_js_dependent_content_is_an_indication_not_a_certainty():
    """No se afirma lo que exigiría renderizar para comprobarse."""
    spa = (
        "<html><head><title>App</title></head><body><div id=\"root\"></div>"
        "<script>" + ("var x=1;" * 4000) + "</script></body></html>"
    )
    _mock(spa)
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await GeoReadinessCheck().run(ctx)

    js = next(f for f in findings if f.id == "content_requires_javascript")
    assert js.severity == "high"
    assert js.confidence == "medium"
    assert "renderizar" in js.finding


# ---------------------------------------------------------------------------
# Datos estructurados y SEO local (§6.3, §6.4)
# ---------------------------------------------------------------------------


@respx.mock
async def test_missing_structured_data_is_reported():
    _mock("<html lang='es'><head><title>Hola</title></head><body><h1>Hola</h1></body></html>")
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await StructuredDataCheck().run(ctx)

    assert any(f.id == "structured_data_missing" for f in findings)


@respx.mock
async def test_malformed_json_ld_is_reported_not_swallowed():
    html = (
        "<html lang='es'><head><title>x</title>"
        '<script type="application/ld+json">{"@type": no-json}</script>'
        "</head><body><h1>x</h1></body></html>"
    )
    _mock(html)
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await StructuredDataCheck().run(ctx)

    assert any(f.id == "structured_data_invalid" for f in findings)


@respx.mock
async def test_well_marked_local_business_produces_no_local_failures():
    _mock()
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await SeoLocalCheck().run(ctx)

    ids = {f.id for f in findings}
    assert "local_business_schema_missing" not in ids
    assert "phone_not_linked" not in ids
    assert "opening_hours_missing" not in ids


# ---------------------------------------------------------------------------
# Rendimiento (§8)
# ---------------------------------------------------------------------------


@respx.mock
async def test_layer_one_never_invents_rendering_metrics():
    """Sin datos de campo no se reportan LCP, CLS ni INP. Jamás se estiman."""
    _mock()
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await PerformanceCheck().run(ctx)

    ids = {f.id for f in findings}
    assert "lcp_poor" not in ids
    assert "inp_poor" not in ids
    assert "cls_poor" not in ids


@respx.mock
async def test_field_data_is_opt_in_and_emits_no_request_without_it():
    """Sin el flag, la URL del cliente no sale hacia ningún tercero."""
    _mock()
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    # `field_data_enabled` no se ha activado.
    findings = await PerformanceCheck().run(ctx)

    assert not any(f.id.startswith("field_data") for f in findings)
    assert not any("pagespeedonline" in str(call.request.url) for call in respx.calls)


@respx.mock
async def test_field_data_requested_without_key_reports_it_and_stays_offline(monkeypatch):
    monkeypatch.delenv("IDATA_PAGESPEED_API_KEY", raising=False)
    _mock()
    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    ctx.field_data_enabled = True
    findings = await PerformanceCheck().run(ctx)

    notice = next(f for f in findings if f.id == "field_data_not_configured")
    assert notice.confidence == "unverified"  # no midió nada: no puede penalizar
    assert not any("pagespeedonline" in str(call.request.url) for call in respx.calls)


@respx.mock
async def test_uncompressed_response_is_reported():
    big = "<html lang='es'><head><title>t</title></head><body>" + ("x" * 40000) + "</body></html>"
    respx.get("https://cliente.test/robots.txt").mock(return_value=httpx.Response(404))
    respx.get(ROOT).mock(return_value=httpx.Response(
        200, text=big, headers={"content-type": "text/html"}))
    respx.route(host="cliente.test").mock(return_value=httpx.Response(404))

    ctx = _ctx()
    ctx.crawl = await crawl(ctx, budget=2)
    findings = await PerformanceCheck().run(ctx)

    assert any(f.id == "response_uncompressed" for f in findings)
