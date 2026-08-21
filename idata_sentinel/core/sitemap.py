"""Descubrimiento y lectura de sitemaps XML (plan SEO/GEO §6.1).

Solo lectura y parseo: la validación de cada URL (que responda 200, que no
mezcle esquemas) la hace el check, que es quien tiene presupuesto de peticiones.

El XML se parsea con `defusedxml` si está disponible y con la librería estándar
si no. Un sitemap es un documento **de un tercero**: parsearlo con un parser XML
permisivo abre la puerta a expansión de entidades y a lecturas de archivos
locales. Aquí se desactivan explícitamente.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

#: Rutas donde vive un sitemap por convención, en orden de probabilidad.
COMMON_PATHS = ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml", "/sitemap1.xml")

_SITEMAP_DIRECTIVE = re.compile(r"^\s*sitemap\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_NS = re.compile(r"^\{[^}]+\}")


@dataclass(frozen=True)
class SitemapEntry:
    loc: str
    lastmod: str | None = None


@dataclass(frozen=True)
class Sitemap:
    url: str
    #: URLs de páginas (`<urlset>`).
    entries: tuple[SitemapEntry, ...] = ()
    #: URLs de otros sitemaps (`<sitemapindex>`).
    children: tuple[str, ...] = ()
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def is_index(self) -> bool:
        return bool(self.children)


def sitemaps_declared_in_robots(robots_text: str) -> list[str]:
    """Directivas `Sitemap:` de un robots.txt.

    Es la fuente preferente: es donde el propio sitio declara cuál es el suyo,
    por encima de adivinarlo en las rutas convencionales.
    """
    return [m.group(1).strip() for m in _SITEMAP_DIRECTIVE.finditer(robots_text or "")]


def _localname(tag: str) -> str:
    return _NS.sub("", tag).lower()


def parse(url: str, xml_text: str) -> Sitemap:
    """Parsea un sitemap. Nunca lanza: un XML roto es un hallazgo, no un crash."""
    if not (xml_text or "").strip():
        return Sitemap(url=url, error="El documento está vacío.")

    try:
        root = _safe_fromstring(xml_text)
    except ElementTree.ParseError as e:
        return Sitemap(url=url, error=f"XML malformado: {e}")
    except ValueError as e:
        return Sitemap(url=url, error=str(e))

    kind = _localname(root.tag)
    if kind == "sitemapindex":
        children = tuple(
            loc for loc in (_child_text(node, "loc") for node in root) if loc
        )
        return Sitemap(url=url, children=children)

    if kind == "urlset":
        entries = tuple(
            SitemapEntry(loc=loc, lastmod=_child_text(node, "lastmod"))
            for node in root
            if (loc := _child_text(node, "loc"))
        )
        return Sitemap(url=url, entries=entries)

    return Sitemap(url=url, error=f"Raíz inesperada <{kind}>: no es urlset ni sitemapindex.")


def _safe_fromstring(xml_text: str) -> ElementTree.Element:
    """Parseo sin resolución de entidades externas.

    `defusedxml` si está instalado; si no, la stdlib, que desde Python 3.8 no
    expande entidades externas por defecto pero sí acepta declaraciones DOCTYPE.
    Se rechazan explícitamente los documentos con DOCTYPE para no depender de ese
    detalle: un sitemap legítimo nunca lo necesita.
    """
    if "<!DOCTYPE" in xml_text[:2048].upper():
        raise ValueError("El documento declara un DOCTYPE; un sitemap no lo requiere.")
    try:
        from defusedxml.ElementTree import fromstring as safe_fromstring  # noqa: PLC0415
    except ImportError:
        return ElementTree.fromstring(xml_text)  # noqa: S314 — DOCTYPE ya rechazado
    return safe_fromstring(xml_text)


def _child_text(node: ElementTree.Element, name: str) -> str | None:
    for child in node:
        if _localname(child.tag) == name:
            return (child.text or "").strip() or None
    return None


def same_site(url: str, base_url: str) -> bool:
    """Si `url` pertenece al mismo sitio, ignorando `www`.

    Un sitemap que lista URLs de otro dominio no es utilizable para rastrear
    este sitio y, por presupuesto, tampoco se sigue.
    """
    host = (urlparse(url).hostname or "").lower().removeprefix("www.")
    base = (urlparse(base_url).hostname or "").lower().removeprefix("www.")
    return bool(host) and host == base


def candidate_urls(target: str, robots_text: str) -> list[str]:
    """Dónde buscar el sitemap: lo declarado en robots primero, luego convención."""
    declared = [u for u in sitemaps_declared_in_robots(robots_text) if same_site(u, target)]
    conventional = [urljoin(target.rstrip("/") + "/", path.lstrip("/")) for path in COMMON_PATHS]
    seen: set[str] = set()
    ordered: list[str] = []
    for url in [*declared, *conventional]:
        if url not in seen:
            seen.add(url)
            ordered.append(url)
    return ordered
