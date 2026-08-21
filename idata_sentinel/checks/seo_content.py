"""¿Se entiende de qué trata cada página? (plan SEO/GEO §6.2)

Estos checks miden **estructura y metadatos**, nunca calidad editorial. La
distinción importa: `thin_content` afirma que se sirvieron pocas palabras, no que
el texto sea malo, y el hallazgo está redactado para decir exactamente eso.
"""
from __future__ import annotations

from collections import Counter
from urllib.parse import urlparse

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.core.crawl import CrawlResult
from idata_sentinel.core.html_parse import (
    headings,
    html_lang,
    images,
    meta_content,
    title_of,
    word_count,
)

_MODULE = "search_visibility"

#: Rangos usuales de recorte en resultados de búsqueda. No son reglas del
#: buscador —no publica ninguna— sino el ancho a partir del cual el texto se
#: trunca en pantalla, que es lo que se está midiendo.
_TITLE_MIN, _TITLE_MAX = 15, 65
_DESC_MIN, _DESC_MAX = 50, 165
_THIN_CONTENT_WORDS = 150


class SeoContentCheck(BaseCheck):
    id = "seo_content"
    category = "Contenido"
    module = _MODULE

    async def run(self, ctx) -> list[CheckResult]:
        crawl: CrawlResult | None = getattr(ctx, "crawl", None)
        if crawl is None or not crawl.html_pages:
            return [self._error_result(
                sub_id="seo_content_unreachable",
                reason="No se obtuvo ninguna página HTML para analizar el contenido.",
            )]

        out: list[CheckResult] = []
        for page in crawl.html_pages:
            out.extend(self._page(page))
        out.extend(self._duplicates(crawl))
        out.extend(self._language(crawl))
        out.extend(self._social(crawl))
        return out

    def _page(self, page) -> list[CheckResult]:
        out: list[CheckResult] = []
        path = _path(page.url)
        html = page.html

        title = title_of(html)
        if not title:
            out.append(self._result(
                sub_id=f"title_missing@{path}",
                severity="high", likelihood="high", status="fail",
                title=f"Sin etiqueta <title> en {path}",
                finding=f"La página {path} no tiene título.",
                business_impact=(
                    "El título es el enlace azul del resultado de búsqueda y lo que se lee en la "
                    "pestaña. Sin él, el buscador inventa uno con el texto que encuentre."
                ),
                recommendation="Escribir un <title> único y descriptivo por página.",
                evidence=path, references=("Google Search Central — títulos",),
            ))
        elif not (_TITLE_MIN <= len(title) <= _TITLE_MAX):
            out.append(self._result(
                sub_id=f"title_length_suboptimal@{path}",
                severity="low", likelihood="medium", status="warning",
                title=f"Título de longitud poco aprovechada en {path}",
                finding=f"El título de {path} tiene {len(title)} caracteres: «{title[:90]}».",
                business_impact=(
                    "Por debajo del rango desaprovecha espacio del resultado; por encima se "
                    "trunca y el usuario no ve el final."
                ),
                recommendation=f"Ajustar el título a entre {_TITLE_MIN} y {_TITLE_MAX} caracteres.",
                evidence=title[:200], references=(),
            ))

        description = meta_content(html, name="description")
        if not description:
            out.append(self._result(
                sub_id=f"meta_description_missing@{path}",
                severity="medium", likelihood="medium", status="fail",
                title=f"Sin meta description en {path}",
                finding=f"La página {path} no declara <meta name=\"description\">.",
                business_impact=(
                    "El buscador arma el resumen del resultado con un fragmento cualquiera de la "
                    "página. Es el texto que decide si alguien entra o sigue de largo."
                ),
                recommendation="Escribir una descripción propia por página.",
                evidence=path, references=(),
            ))
        elif not (_DESC_MIN <= len(description) <= _DESC_MAX):
            out.append(self._result(
                sub_id=f"meta_description_length@{path}",
                severity="low", likelihood="low", status="warning",
                title=f"Descripción de longitud poco aprovechada en {path}",
                finding=f"La descripción de {path} tiene {len(description)} caracteres.",
                business_impact="El resumen del resultado se corta o queda demasiado escueto.",
                recommendation=f"Ajustar a entre {_DESC_MIN} y {_DESC_MAX} caracteres.",
                evidence=description[:200], references=(),
            ))

        hs = headings(html)
        h1s = [h for h in hs if h.level == 1]
        if not h1s:
            out.append(self._result(
                sub_id=f"h1_missing@{path}",
                severity="medium", likelihood="high", status="fail",
                title=f"Sin encabezado H1 en {path}",
                finding=f"La página {path} no tiene ningún <h1>.",
                business_impact=(
                    "El H1 es la declaración principal del tema de la página, y también lo que "
                    "un motor generativo usa para saber de qué trata antes de citarla."
                ),
                recommendation="Poner un único H1 que describa el contenido de la página.",
                evidence=path, references=(),
            ))
        elif len(h1s) > 1:
            out.append(self._result(
                sub_id=f"h1_multiple@{path}",
                severity="low", likelihood="medium", status="warning",
                title=f"Varios H1 en {path}",
                finding=f"{path} tiene {len(h1s)} encabezados H1: {'; '.join(h.text[:40] for h in h1s[:3])}.",
                business_impact="Con varios H1 se diluye cuál es el tema principal de la página.",
                recommendation="Dejar un solo H1 y bajar los demás a H2.",
                evidence="; ".join(h.text[:60] for h in h1s[:4])[:300], references=(),
            ))

        if _hierarchy_broken(hs):
            out.append(self._result(
                sub_id=f"heading_hierarchy_broken@{path}",
                severity="low", likelihood="low", status="warning",
                title=f"Jerarquía de encabezados con saltos en {path}",
                finding=(
                    "Los encabezados saltan niveles (por ejemplo de H2 a H4), lo que rompe el "
                    "esquema del documento."
                ),
                business_impact=(
                    "Buscadores, motores generativos y lectores de pantalla usan la jerarquía "
                    "para entender la estructura. Un salto la vuelve ambigua."
                ),
                recommendation="Usar los niveles en orden, sin saltarse ninguno.",
                evidence=" > ".join(f"H{h.level}" for h in hs[:12]), references=("WCAG 1.3.1",),
            ))

        imgs = images(html)
        missing_alt = [i for i in imgs if i.alt is None]
        if imgs and missing_alt:
            out.append(self._result(
                sub_id=f"images_without_alt@{path}",
                severity="low", likelihood="high", status="warning",
                title=f"Imágenes sin atributo alt en {path}",
                finding=(
                    f"{len(missing_alt)} de {len(imgs)} imágenes de {path} no declaran `alt`. "
                    "Un `alt` vacío es válido para imágenes decorativas; aquí el atributo falta."
                ),
                business_impact=(
                    "El texto alternativo es lo único que describe la imagen a un buscador y a "
                    "quien usa lector de pantalla. También es requisito de accesibilidad."
                ),
                recommendation="Añadir `alt` descriptivo, o `alt=\"\"` si la imagen es decorativa.",
                evidence="; ".join(i.src[:60] for i in missing_alt[:3])[:300],
                references=("WCAG 1.1.1",),
            ))

        words = word_count(html)
        if words < _THIN_CONTENT_WORDS:
            out.append(self._result(
                sub_id=f"thin_content@{path}",
                severity="low", likelihood="medium", status="warning", confidence="medium",
                title=f"Poco texto servido en {path}",
                finding=(
                    f"La página {path} sirve {words} palabras visibles en el HTML. Se mide el "
                    "texto entregado por el servidor, no la calidad del contenido."
                ),
                business_impact=(
                    "Con poco texto hay pocas señales sobre el tema de la página, y un motor "
                    "generativo tiene poco que citar. Si el contenido se carga por JavaScript, "
                    "el problema es otro y está en el hallazgo de renderizado."
                ),
                recommendation="Ampliar el contenido servido, o comprobar si depende de JavaScript.",
                evidence=f"{words} palabras", references=(),
            ))
        return out

    def _duplicates(self, crawl: CrawlResult) -> list[CheckResult]:
        """Títulos o descripciones repetidos entre páginas distintas."""
        out: list[CheckResult] = []
        pages = crawl.html_pages
        if len(pages) < 2:
            return out

        for label, sub_id, extract in (
            ("títulos", "title_duplicated", lambda h: title_of(h)),
            ("descripciones", "meta_description_duplicated",
             lambda h: meta_content(h, name="description")),
        ):
            values = [(p, extract(p.html)) for p in pages]
            counts = Counter(v for _, v in values if v)
            repeated = {v for v, n in counts.items() if n > 1}
            if not repeated:
                continue
            affected = [_path(p.url) for p, v in values if v in repeated]
            out.append(self._result(
                sub_id=sub_id,
                severity="medium", likelihood="medium", status="fail",
                title=f"Hay {label} repetidos entre páginas",
                finding=(
                    f"{len(affected)} páginas comparten {label}: {', '.join(affected[:5])}."
                ),
                business_impact=(
                    "Páginas distintas se presentan como si fueran lo mismo. El buscador elige "
                    "una y relega las demás, y el usuario no distingue los resultados entre sí."
                ),
                recommendation=f"Escribir {label} únicos por página.",
                evidence="; ".join(sorted(repeated)[:3])[:300], references=(),
            ))
        return out

    def _language(self, crawl: CrawlResult) -> list[CheckResult]:
        root = crawl.root
        if root is None or not root.html:
            return []
        if html_lang(root.html):
            return []
        return [self._result(
            sub_id="lang_not_declared",
            severity="low", likelihood="high", status="fail",
            title="El idioma del sitio no está declarado",
            finding="La etiqueta <html> no declara el atributo `lang`.",
            business_impact=(
                "El buscador tiene que adivinar el idioma para decidir en qué mercado mostrar el "
                "sitio, y los lectores de pantalla eligen mal la pronunciación."
            ),
            recommendation="Declarar <html lang=\"es-CL\"> (o el idioma que corresponda).",
            evidence="<html> sin lang", references=("WCAG 3.1.1",),
        )]

    def _social(self, crawl: CrawlResult) -> list[CheckResult]:
        root = crawl.root
        if root is None or not root.html:
            return []
        html = root.html
        missing = [
            tag for tag in ("og:title", "og:description", "og:image")
            if not meta_content(html, prop=tag)
        ]
        if not missing:
            return []
        return [self._result(
            sub_id="open_graph_incomplete",
            severity="low", likelihood="medium", status="warning",
            title="Faltan metadatos para compartir el sitio",
            finding=f"La portada no declara: {', '.join(missing)}.",
            business_impact=(
                "Al compartir el enlace por WhatsApp, LinkedIn o correo, la vista previa sale "
                "sin imagen ni descripción. En un negocio que capta por WhatsApp, esa vista "
                "previa es la primera impresión."
            ),
            recommendation="Declarar og:title, og:description y og:image en cada página.",
            evidence=", ".join(missing), references=("Open Graph protocol",),
        )]


def _hierarchy_broken(hs: list) -> bool:
    previous = 0
    for h in hs:
        if previous and h.level > previous + 1:
            return True
        previous = h.level
    return False


def _path(url: str) -> str:
    return urlparse(url).path or "/"
