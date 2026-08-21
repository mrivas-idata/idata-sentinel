"""Extracción de elementos del HTML, compartida entre módulos.

Vive en `core/` porque tres módulos necesitan leer lo mismo del mismo documento:
el análisis de JavaScript (Módulo 1), las señales de privacidad (Módulo 3) y la
visibilidad en buscadores (Módulo 5). Tenerlo duplicado por check ya causó un
problema real una vez —la emisión de hallazgos de CVE quedó copiada en dos
checks hasta que se unificó—, y aquí el riesgo era mayor: tres copias del mismo
parser divergiendo en silencio.

Es deliberadamente de expresiones regulares, no un árbol DOM: el objetivo es
leer lo que el servidor **sirvió**, tolerando HTML roto, sin sumar una
dependencia de parseo ni el coste de construir un árbol para leer seis
atributos.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

_TAG_META = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_TAG_LINK = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
_TAG_A = re.compile(r"<a\b([^>]*)>(.*?)</a>", re.IGNORECASE | re.DOTALL)
_TAG_IMG = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
_TAG_SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_TAG_TITLE = re.compile(r"<title\b[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TAG_HEADING = re.compile(r"<h([1-6])\b[^>]*>(.*?)</h\1>", re.IGNORECASE | re.DOTALL)
_TAG_HTML = re.compile(r"<html\b([^>]*)>", re.IGNORECASE)
_TAG_HEAD = re.compile(r"<head\b[^>]*>(.*?)</head>", re.IGNORECASE | re.DOTALL)

_ATTR = re.compile(
    r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"""
)
_STRIP_TAGS = re.compile(r"<(script|style|noscript|template)\b.*?</\1>", re.IGNORECASE | re.DOTALL)
_ANY_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def attrs_of(raw: str) -> dict[str, str]:
    """Atributos de una etiqueta, en minúsculas y sin distinguir comillas."""
    out: dict[str, str] = {}
    for m in _ATTR.finditer(raw):
        key = m.group(1).lower()
        out[key] = m.group(2) or m.group(3) or m.group(4) or ""
    return out


def visible_text(html: str) -> str:
    """Texto que un lector vería, sin scripts, estilos ni etiquetas.

    Es la base de dos medidas distintas: el volumen de contenido servido (SEO) y
    la proporción texto/JavaScript que delata una página cuyo contenido solo
    existe tras renderizar (GEO).
    """
    without_code = _STRIP_TAGS.sub(" ", html or "")
    return _WS.sub(" ", _ANY_TAG.sub(" ", without_code)).strip()


def word_count(html: str) -> int:
    text = visible_text(html)
    return len([w for w in text.split(" ") if w])


def title_of(html: str) -> str | None:
    m = _TAG_TITLE.search(html or "")
    if not m:
        return None
    return _WS.sub(" ", _ANY_TAG.sub("", m.group(1))).strip() or None


def html_lang(html: str) -> str | None:
    m = _TAG_HTML.search(html or "")
    if not m:
        return None
    return attrs_of(m.group(1)).get("lang") or None


def meta_tags(html: str) -> list[dict[str, str]]:
    return [attrs_of(m.group(0)) for m in _TAG_META.finditer(html or "")]


def meta_content(html: str, *, name: str | None = None, prop: str | None = None) -> str | None:
    """Contenido de un `<meta>` por `name` o por `property` (Open Graph)."""
    wanted = (name or prop or "").lower()
    key = "name" if name else "property"
    for tag in meta_tags(html):
        if tag.get(key, "").lower() == wanted:
            return tag.get("content", "").strip() or None
    return None


def link_tags(html: str, rel: str | None = None) -> list[dict[str, str]]:
    tags = [attrs_of(m.group(0)) for m in _TAG_LINK.finditer(html or "")]
    if rel is None:
        return tags
    return [t for t in tags if rel.lower() in t.get("rel", "").lower().split()]


@dataclass(frozen=True)
class Heading:
    level: int
    text: str


def headings(html: str) -> list[Heading]:
    out: list[Heading] = []
    for m in _TAG_HEADING.finditer(html or ""):
        text = _WS.sub(" ", _ANY_TAG.sub("", m.group(2))).strip()
        out.append(Heading(level=int(m.group(1)), text=text))
    return out


@dataclass(frozen=True)
class Image:
    src: str
    alt: str | None
    has_dimensions: bool
    lazy: bool


def images(html: str) -> list[Image]:
    out: list[Image] = []
    for m in _TAG_IMG.finditer(html or ""):
        a = attrs_of(m.group(0))
        out.append(Image(
            src=a.get("src", ""),
            # `alt=""` es válido y deliberado (imagen decorativa): se distingue
            # de la ausencia del atributo, que es lo que sí es un hallazgo.
            alt=a.get("alt") if "alt" in a else None,
            has_dimensions=bool(a.get("width") and a.get("height")),
            lazy=a.get("loading", "").lower() == "lazy",
        ))
    return out


@dataclass(frozen=True)
class Anchor:
    href: str
    absolute: str
    text: str
    rel: str
    internal: bool


def anchors(html: str, base_url: str) -> list[Anchor]:
    base_host = (urlparse(base_url).hostname or "").lower().removeprefix("www.")
    out: list[Anchor] = []
    for m in _TAG_A.finditer(html or ""):
        a = attrs_of(m.group(1))
        href = (a.get("href") or "").strip()
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        absolute = urljoin(base_url, href)
        host = (urlparse(absolute).hostname or "").lower().removeprefix("www.")
        out.append(Anchor(
            href=href, absolute=absolute,
            text=_WS.sub(" ", _ANY_TAG.sub("", m.group(2))).strip(),
            rel=a.get("rel", ""),
            internal=host == base_host,
        ))
    return out


@dataclass(frozen=True)
class ScriptTag:
    src: str | None
    body: str
    attrs: dict[str, str] = field(default_factory=dict)

    @property
    def blocking(self) -> bool:
        """Un script externo sin `async` ni `defer` bloquea el parseo del HTML."""
        if not self.src:
            return False
        return not ("async" in self.attrs or "defer" in self.attrs)


def scripts(html: str) -> list[ScriptTag]:
    out: list[ScriptTag] = []
    for m in _TAG_SCRIPT.finditer(html or ""):
        a = attrs_of(m.group(1))
        out.append(ScriptTag(src=a.get("src") or None, body=m.group(2) or "", attrs=a))
    return out


def head_html(html: str) -> str:
    m = _TAG_HEAD.search(html or "")
    return m.group(1) if m else ""


def json_ld_blocks(html: str) -> tuple[list[object], list[str]]:
    """Bloques JSON-LD parseados y los errores de los que no se pudieron leer.

    Devuelve los errores además de los datos porque un JSON-LD malformado es en
    sí mismo un hallazgo —el buscador tampoco lo va a poder leer—, y descartarlo
    en silencio lo haría invisible.
    """
    parsed: list[object] = []
    errors: list[str] = []
    for tag in scripts(html):
        if tag.attrs.get("type", "").lower().strip() != "application/ld+json":
            continue
        raw = tag.body.strip()
        if not raw:
            continue
        try:
            parsed.append(json.loads(raw))
        except json.JSONDecodeError as e:
            errors.append(f"{e.msg} (línea {e.lineno})")
    return parsed, errors


def schema_types(blocks: list[object]) -> set[str]:
    """`@type` presentes en los bloques, incluidos los anidados en `@graph`."""
    found: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        raw_type = node.get("@type")
        if isinstance(raw_type, str):
            found.add(raw_type)
        elif isinstance(raw_type, list):
            found.update(t for t in raw_type if isinstance(t, str))
        for value in node.values():
            if isinstance(value, (dict, list)):
                walk(value)

    walk(blocks)
    return found


def schema_nodes(blocks: list[object], wanted: str) -> list[dict]:
    """Nodos cuyo `@type` coincide con `wanted`, sin distinguir mayúsculas."""
    out: list[dict] = []

    def walk(node: object) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return
        raw_type = node.get("@type")
        types = [raw_type] if isinstance(raw_type, str) else (raw_type or [])
        if any(isinstance(t, str) and t.lower() == wanted.lower() for t in types):
            out.append(node)
        for value in node.values():
            if isinstance(value, (dict, list)):
                walk(value)

    walk(blocks)
    return out
