"""Rastreo acotado de páginas para el módulo de visibilidad (plan SEO/GEO §5).

Con ≥2 s entre peticiones al mismo host, rastrear un sitio entero convertiría un
escaneo de tres minutos en uno de veinte y haría inviable el monitoreo semanal de
una cartera. Por eso el rastreo tiene un **presupuesto explícito** y, cuando se
agota, lo declara: un análisis parcial nunca se presenta como completo.

Vive en `core/` y no en el módulo porque `ScanContext` guarda el resultado, y
`core/` no puede depender de `modules/`.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from idata_sentinel.core import sitemap as sitemap_mod
from idata_sentinel.core.html_parse import anchors
from idata_sentinel.core.http_client import FetchOutcome

#: Presupuesto por defecto. Ocho páginas cubren portada, un par de secciones y
#: la comprobación de 404 sin que el escaneo deje de ser razonable en tiempo.
DEFAULT_PAGE_BUDGET = 8
MAX_PAGE_BUDGET = 50

#: Cuántas páginas como mucho se toman de cada fuente, para que un sitemap
#: gigante no consuma el presupuesto entero y deje la navegación sin mirar.
_MAX_FROM_SITEMAP = 3
_MAX_FROM_NAV = 3


@dataclass(frozen=True)
class CrawledPage:
    url: str
    outcome: FetchOutcome
    #: De dónde salió la URL: "root", "sitemap", "nav" o "probe_404".
    source: str

    @property
    def ok(self) -> bool:
        return self.outcome.ok

    @property
    def status(self) -> int | None:
        return self.outcome.response.status_code if self.outcome.ok else None

    @property
    def html(self) -> str:
        if not self.outcome.ok:
            return ""
        content_type = self.outcome.response.headers.get("content-type", "")
        if "html" not in content_type.lower():
            return ""
        return self.outcome.response.text or ""


@dataclass
class CrawlResult:
    """Lo que el módulo pudo mirar, y lo que quedó fuera.

    `skipped` y `budget` no son telemetría: son parte del hallazgo. Un informe
    que no diga cuántas páginas quedaron sin rastrear está insinuando que las vio
    todas.
    """

    pages: list[CrawledPage] = field(default_factory=list)
    sitemaps: list[sitemap_mod.Sitemap] = field(default_factory=list)
    #: URLs conocidas que no se pidieron por falta de presupuesto.
    skipped: list[str] = field(default_factory=list)
    budget: int = DEFAULT_PAGE_BUDGET
    #: URL inexistente usada para comprobar el manejo de 404, si se llegó a pedir.
    probe_404: CrawledPage | None = None
    robots_text: str = ""

    @property
    def html_pages(self) -> list[CrawledPage]:
        """Páginas que respondieron **200** con HTML y sirven para analizar contenido.

        El código de estado no es un detalle: una página de error no tiene por
        qué declarar título, canónica ni H1, y evaluarla como si fuera contenido
        producía hallazgos falsos sobre páginas que el sitio nunca publicó.
        """
        return [
            p for p in self.pages
            if p.source != "probe_404" and p.status == 200 and p.html
        ]

    @property
    def root(self) -> CrawledPage | None:
        return next((p for p in self.pages if p.source == "root"), None)

    @property
    def complete(self) -> bool:
        return not self.skipped


def _normalize(url: str) -> str:
    """Sin fragmento y sin barra final, para no pedir dos veces la misma página."""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}" + (f"?{parsed.query}" if parsed.query else "")


async def crawl(ctx, *, budget: int = DEFAULT_PAGE_BUDGET) -> CrawlResult:
    """Rastrea hasta `budget` páginas del objetivo.

    Orden deliberado: la raíz (ya en caché, coste cero), luego el sitemap —que es
    lo que el propio sitio declara importante—, luego la navegación, y por último
    una sola URL inexistente para comprobar el manejo de 404.
    """
    budget = max(1, min(budget, MAX_PAGE_BUDGET))
    result = CrawlResult(budget=budget)
    base = ctx.target.rstrip("/")

    root_outcome = await ctx.get_outcome("/")
    root_page = CrawledPage(url=base or ctx.target, outcome=root_outcome, source="root")
    result.pages.append(root_page)
    seen = {_normalize(root_page.url)}

    # El texto viene de la política que el engine ya obtuvo, no de una petición
    # nueva. Además de ahorrarla, evita una trampa: con `Disallow: /` el propio
    # filtro de robots impediría releer robots.txt, y el módulo se quedaría sin
    # ver justamente la regla que necesita reportar.
    result.robots_text = getattr(ctx.robots, "text", "") or ""

    candidates: list[tuple[str, str]] = []

    for url in await _sitemap_urls(ctx, result, base):
        candidates.append((url, "sitemap"))

    if root_page.html:
        internal = [
            a.absolute for a in anchors(root_page.html, root_page.url)
            if a.internal and sitemap_mod.same_site(a.absolute, base)
        ]
        taken = 0
        for url in internal:
            if taken >= _MAX_FROM_NAV:
                break
            if _normalize(url) in seen or any(_normalize(url) == _normalize(c) for c, _ in candidates):
                continue
            candidates.append((url, "nav"))
            taken += 1

    # Una página se reserva para la comprobación de 404, si el presupuesto da.
    page_budget = budget - 1 if budget > 2 else budget

    for url, source in candidates:
        key = _normalize(url)
        if key in seen:
            continue
        if len(result.pages) >= page_budget:
            result.skipped.append(url)
            continue
        seen.add(key)
        outcome = await ctx.get_outcome(_path_of(url, base))
        result.pages.append(CrawledPage(url=url, outcome=outcome, source=source))

    if budget > 2:
        result.probe_404 = await _probe_404(ctx, base)
        if result.probe_404 is not None:
            result.pages.append(result.probe_404)

    return result


def _path_of(url: str, base: str) -> str:
    """Ruta relativa al objetivo; absoluta si el host difiere (no debería)."""
    parsed = urlparse(url)
    base_host = (urlparse(base).hostname or "").lower()
    if (parsed.hostname or "").lower() != base_host:
        return url
    return parsed.path + (f"?{parsed.query}" if parsed.query else "") or "/"


async def _sitemap_urls(ctx, result: CrawlResult, base: str) -> list[str]:
    """URLs del primer sitemap que responda, priorizando `lastmod` reciente.

    Se prueba **una sola** ruta convencional además de las declaradas en
    robots.txt: recorrer las cuatro gastaría presupuesto en 404 previsibles.
    """
    candidates = sitemap_mod.candidate_urls(base, result.robots_text)
    declared = sitemap_mod.sitemaps_declared_in_robots(result.robots_text)
    to_try = candidates[: max(1, len(declared)) + 1]

    for url in to_try:
        outcome = await ctx.get_outcome(_path_of(url, base))
        if not outcome.ok or outcome.response.status_code != 200:
            continue
        parsed = sitemap_mod.parse(url, outcome.response.text or "")
        result.sitemaps.append(parsed)
        if not parsed.ok:
            return []
        if parsed.is_index:
            # Un índice: se sigue solo el primer hijo, otra vez por presupuesto.
            for child in parsed.children[:1]:
                child_outcome = await ctx.get_outcome(_path_of(child, base))
                if child_outcome.ok and child_outcome.response.status_code == 200:
                    child_map = sitemap_mod.parse(child, child_outcome.response.text or "")
                    result.sitemaps.append(child_map)
                    return _prioritized(child_map, base)
            return []
        return _prioritized(parsed, base)
    return []


def _prioritized(parsed: sitemap_mod.Sitemap, base: str) -> list[str]:
    entries = [e for e in parsed.entries if sitemap_mod.same_site(e.loc, base)]
    entries.sort(key=lambda e: (e.lastmod is None, e.lastmod or ""), reverse=False)
    with_date = [e for e in entries if e.lastmod]
    with_date.sort(key=lambda e: e.lastmod or "", reverse=True)
    without_date = [e for e in entries if not e.lastmod]
    ordered = [*with_date, *without_date]
    return [e.loc for e in ordered[:_MAX_FROM_SITEMAP]]


async def _probe_404(ctx, base: str) -> CrawledPage | None:
    """Pide **una** URL que no existe, para ver si el sitio la maneja bien.

    No es fuzzing ni descubrimiento de contenido: es una sola ruta generada al
    azar que por construcción no corresponde a nada, y no se busca en ella
    ningún recurso oculto. Sirve para detectar el *soft 404* —contenido servido
    con código 200— que hace que un buscador indexe páginas de error.
    """
    probe = urljoin(base + "/", f"idata-sentinel-404-{uuid.uuid4().hex[:10]}")
    outcome = await ctx.get_outcome(_path_of(probe, base))
    return CrawledPage(url=probe, outcome=outcome, source="probe_404")
