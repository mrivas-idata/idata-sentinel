"""¿Pueden los buscadores entrar, rastrear y entender el sitio? (plan SEO/GEO §6.1)

Este archivo concentra los hallazgos que no son mejoras incrementales sino la
diferencia entre existir y no existir en el índice. Un `noindex` en producción es
a la visibilidad lo que un certificado vencido a la seguridad: no es que el sitio
esté peor posicionado, es que no está.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.core.crawl import CrawlResult
from idata_sentinel.core.html_parse import link_tags, meta_content, word_count

_MODULE = "search_visibility"

#: Un `Disallow: /` para `*` deja fuera a los buscadores generales.
_GENERAL_AGENTS = ("*", "googlebot", "bingbot")


class SeoIndexabilityCheck(BaseCheck):
    id = "seo_indexability"
    category = "Indexabilidad"
    module = _MODULE

    async def run(self, ctx) -> list[CheckResult]:
        crawl: CrawlResult | None = getattr(ctx, "crawl", None)
        if crawl is None:
            return [self._error_result(
                sub_id="seo_indexability_unreachable",
                reason="No se pudo obtener la página principal para evaluar la indexabilidad.",
            )]

        # Las reglas de robots.txt se evalúan siempre, incluso si no se pudo
        # rastrear: cuando el bloqueo es la causa de que no haya nada que mirar,
        # el bloqueo es justamente el hallazgo, y declararlo "no evaluable"
        # escondería el problema más grave que puede tener un sitio en este eje.
        out: list[CheckResult] = list(self._robots_rules(ctx, crawl))

        if crawl.root is None or not crawl.root.ok:
            out.append(self._error_result(
                sub_id="seo_indexability_unreachable",
                reason="No se pudo obtener la página principal para evaluar la indexabilidad.",
            ))
            return out

        out.extend(self._noindex(crawl))
        out.extend(self._canonical(crawl))
        out.extend(self._sitemap(crawl))
        out.extend(self._soft_404(crawl))
        out.extend(self._coverage(crawl))
        return out

    # -- robots.txt ----------------------------------------------------------

    def _robots_rules(self, ctx, crawl: CrawlResult) -> list[CheckResult]:
        text = crawl.robots_text
        if not text.strip():
            return [self._result(
                sub_id="robots_txt_missing",
                severity="low", likelihood="medium", status="warning",
                title="Sin robots.txt",
                finding="No se encontró /robots.txt o no devolvió contenido.",
                business_impact=(
                    "Sin robots.txt los buscadores rastrean todo lo que encuentren, incluidas "
                    "rutas que no aportan y consumen presupuesto de rastreo. Tampoco hay dónde "
                    "declarar el sitemap."
                ),
                recommendation="Publicar /robots.txt declarando el sitemap y las rutas a excluir.",
                evidence="/robots.txt", references=("robots.txt",),
            )]

        blocked = _blocks_everything(text)
        if blocked:
            return [self._result(
                sub_id="robots_blocks_indexing",
                severity="critical", likelihood="high", status="fail",
                title="robots.txt impide el rastreo de todo el sitio",
                finding=(
                    f"robots.txt contiene una regla que bloquea el sitio completo para "
                    f"{blocked}. Los buscadores no pueden rastrear ninguna página."
                ),
                business_impact=(
                    "El sitio no puede aparecer en resultados de búsqueda. No es una cuestión "
                    "de posicionamiento: es ausencia total del índice."
                ),
                recommendation=(
                    "Retirar la regla `Disallow: /` de producción. Si se usa para un entorno de "
                    "pruebas, comprobar que no se haya desplegado por error al sitio real."
                ),
                evidence=_first_disallow_all(text), references=("robots.txt",),
            )]
        return []

    # -- meta robots / X-Robots-Tag -----------------------------------------

    def _noindex(self, crawl: CrawlResult) -> list[CheckResult]:
        out: list[CheckResult] = []
        for page in crawl.html_pages:
            directives = (meta_content(page.html, name="robots") or "").lower()
            header = ""
            if page.outcome.ok:
                header = (page.outcome.response.headers.get("x-robots-tag") or "").lower()

            if "noindex" in directives:
                out.append(self._noindex_result(
                    sub_id=f"meta_robots_noindex@{_path(page.url)}",
                    where=f"la etiqueta <meta name=\"robots\"> de {_path(page.url)}",
                    evidence=directives[:200],
                ))
            if "noindex" in header:
                out.append(self._noindex_result(
                    sub_id=f"x_robots_tag_noindex@{_path(page.url)}",
                    where=f"la cabecera X-Robots-Tag de {_path(page.url)}",
                    evidence=f"X-Robots-Tag: {header[:180]}",
                ))
        return out

    def _noindex_result(self, *, sub_id: str, where: str, evidence: str) -> CheckResult:
        return self._result(
            sub_id=sub_id,
            severity="critical", likelihood="high", status="fail",
            title="La página se declara no indexable",
            finding=f"Se encontró la directiva `noindex` en {where}.",
            business_impact=(
                "La página queda fuera del índice de los buscadores. Es el hallazgo que con más "
                "frecuencia aparece por un despliegue: la directiva se pone en el entorno de "
                "pruebas y viaja a producción sin que nadie lo note."
            ),
            recommendation="Retirar `noindex` de las páginas que deban aparecer en buscadores.",
            evidence=evidence, references=("Google Search Central — noindex",),
        )

    # -- canonical -----------------------------------------------------------

    def _canonical(self, crawl: CrawlResult) -> list[CheckResult]:
        out: list[CheckResult] = []
        for page in crawl.html_pages:
            canonicals = [t.get("href", "") for t in link_tags(page.html, rel="canonical")]
            canonicals = [c for c in canonicals if c.strip()]
            path = _path(page.url)

            if not canonicals:
                out.append(self._result(
                    sub_id=f"canonical_missing@{path}",
                    severity="medium", likelihood="medium", status="fail",
                    title=f"Sin URL canónica declarada en {path}",
                    finding=f"La página {path} no declara <link rel=\"canonical\">.",
                    business_impact=(
                        "Sin canónica, el buscador decide por su cuenta cuál de las variantes de "
                        "la URL indexar. Las versiones con y sin www, con parámetros de campaña o "
                        "con barra final compiten entre sí y reparten la autoridad."
                    ),
                    recommendation="Declarar la URL canónica absoluta en cada página.",
                    evidence=path, references=("Google Search Central — canonical",),
                ))
                continue

            target = urljoin(page.url, canonicals[0])
            if not _same_host(target, page.url):
                out.append(self._result(
                    sub_id=f"canonical_conflict@{path}",
                    severity="high", likelihood="high", status="fail",
                    title=f"La URL canónica de {path} apunta a otro dominio",
                    finding=f"{path} declara como canónica {target}, que no pertenece a este sitio.",
                    business_impact=(
                        "El sitio le está cediendo la indexación de esta página a otro dominio. "
                        "Suele ser rastro de una plantilla copiada o de una migración a medias."
                    ),
                    recommendation="Corregir la canónica para que apunte a la URL definitiva de este sitio.",
                    evidence=target, references=("Google Search Central — canonical",),
                ))
        return out

    # -- sitemap -------------------------------------------------------------

    def _sitemap(self, crawl: CrawlResult) -> list[CheckResult]:
        if not crawl.sitemaps:
            return [self._result(
                sub_id="sitemap_missing",
                severity="medium", likelihood="high", status="fail",
                title="Sin sitemap.xml accesible",
                finding=(
                    "No se encontró sitemap ni declarado en robots.txt ni en las rutas "
                    "convencionales."
                ),
                business_impact=(
                    "El buscador descubre las páginas solo siguiendo enlaces. Las secciones poco "
                    "enlazadas desde la navegación tardan más en indexarse o no se indexan."
                ),
                recommendation="Publicar sitemap.xml y declararlo en robots.txt con `Sitemap:`.",
                evidence="/sitemap.xml, /sitemap_index.xml", references=("sitemaps.org",),
            )]

        out: list[CheckResult] = []
        for sm in crawl.sitemaps:
            if not sm.ok:
                out.append(self._result(
                    sub_id=f"sitemap_invalid@{_path(sm.url)}",
                    severity="medium", likelihood="high", status="fail",
                    title="El sitemap no se puede leer",
                    finding=f"{sm.url} no es un sitemap válido: {sm.error}",
                    business_impact=(
                        "Un sitemap que el buscador no puede parsear equivale a no tenerlo, con "
                        "el agravante de que nadie lo revisa porque el archivo existe."
                    ),
                    recommendation="Regenerar el sitemap y validar que sea XML bien formado.",
                    evidence=str(sm.error)[:200], references=("sitemaps.org",),
                ))
                continue

            mixed = [e.loc for e in sm.entries if e.loc.startswith("http://")]
            if mixed:
                out.append(self._result(
                    sub_id=f"sitemap_mixed_scheme@{_path(sm.url)}",
                    severity="low", likelihood="high", status="warning",
                    title="El sitemap declara URLs por HTTP",
                    finding=f"{len(mixed)} URL(s) del sitemap usan http:// en un sitio servido por HTTPS.",
                    business_impact=(
                        "El buscador recibe señales contradictorias sobre cuál es la versión "
                        "buena de cada página y gasta rastreo en redirecciones."
                    ),
                    recommendation="Regenerar el sitemap con todas las URLs en https://.",
                    evidence="; ".join(mixed[:3])[:300], references=("sitemaps.org",),
                ))
        return out

    # -- soft 404 ------------------------------------------------------------

    def _soft_404(self, crawl: CrawlResult) -> list[CheckResult]:
        probe = crawl.probe_404
        if probe is None or not probe.ok:
            return []
        if probe.status != 200:
            return []
        return [self._result(
            sub_id="soft_404",
            severity="medium", likelihood="high", status="fail",
            title="Las páginas inexistentes responden 200 en vez de 404",
            finding=(
                f"Se pidió una URL generada al azar que no existe y el servidor respondió "
                f"200 con {word_count(probe.html)} palabras de contenido, en vez de 404."
            ),
            business_impact=(
                "El buscador indexa como páginas reales URLs que no existen: enlaces rotos, "
                "direcciones mal escritas y rutas antiguas acaban en el índice compitiendo con "
                "el contenido bueno."
            ),
            recommendation="Devolver 404 (o 410) en las rutas inexistentes, con la página de error propia.",
            evidence=f"{probe.url} -> HTTP {probe.status}", references=("Google Search Central — soft 404",),
        )]

    # -- cobertura del rastreo ----------------------------------------------

    def _coverage(self, crawl: CrawlResult) -> list[CheckResult]:
        """Declara qué quedó fuera. No penaliza: es una limitación nuestra."""
        if crawl.complete:
            return []
        return [self._result(
            sub_id="seo_crawl_incomplete",
            severity="info", likelihood="low", status="warning", confidence="high",
            title="El análisis no cubrió todas las páginas conocidas",
            finding=(
                f"Se analizaron {len(crawl.html_pages)} página(s) con un presupuesto de "
                f"{crawl.budget}; quedaron {len(crawl.skipped)} URL(s) conocidas sin revisar. "
                "Los hallazgos de contenido describen solo lo analizado."
            ),
            business_impact=(
                "El diagnóstico es válido para las páginas revisadas y no puede extenderse al "
                "resto del sitio sin ampliarlo."
            ),
            recommendation="Repetir con --seo-pages mayor si se necesita cobertura completa.",
            evidence="; ".join(crawl.skipped[:5])[:300], references=(),
        )]


def _blocks_everything(text: str) -> str | None:
    """Agentes generales con `Disallow: /` sin `Allow:` que lo rescate."""
    current: list[str] = []
    blocked: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field_name, _, value = line.partition(":")
        field_name = field_name.strip().lower()
        value = value.strip()
        if field_name == "user-agent":
            current = [value.lower()]
        elif field_name == "disallow" and value == "/":
            blocked.update(a for a in current if a in _GENERAL_AGENTS)
    return ", ".join(sorted(blocked)) or None


def _first_disallow_all(text: str) -> str:
    for raw in text.splitlines():
        if raw.split("#", 1)[0].strip().lower().replace(" ", "") == "disallow:/":
            return raw.strip()
    return "Disallow: /"


def _path(url: str) -> str:
    return urlparse(url).path or "/"


def _same_host(a: str, b: str) -> bool:
    ha = (urlparse(a).hostname or "").lower().removeprefix("www.")
    hb = (urlparse(b).hostname or "").lower().removeprefix("www.")
    return ha == hb
