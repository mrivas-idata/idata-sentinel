"""Documentos en Markdown → PDF con identidad IDATA (plan maestro §8).

Reutiliza el pipeline de WeasyPrint del reporte, pero para documentos largos de
texto: la guía del cliente, propuestas, informes de acompañamiento.

**Por qué el fondo es claro y no el oscuro del reporte.** El reporte ejecutivo es
una pieza de presentación de nueve secciones; esto son treinta páginas pensadas
para leerse, anotarse y firmarse en papel. Un documento largo sobre fondo oscuro
es incómodo de leer e impracticable de imprimir. Se conserva la identidad —el
azul de marca, la tipografía, el tratamiento de portada— y se invierte el fondo
del cuerpo. La portada sí mantiene el fondo oscuro: una página, y da carácter.

El Markdown es la fuente única: IDATA lo edita sin tocar código y el mismo
archivo se lee en el repositorio y se entrega en PDF.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import markdown
from markdown.extensions.toc import slugify_unicode

from idata_sentinel.reporting.branding import load_branding

#: Bloques que solo existen para el equipo de IDATA. Se eliminan por defecto:
#: automatizarlo evita el error de entregar notas internas al cliente.
_INTERNAL_BLOCK = re.compile(
    r"<!--\s*interno:inicio\s*-->.*?<!--\s*interno:fin\s*-->", re.DOTALL | re.IGNORECASE
)
_H1 = re.compile(r"^#\s+(?P<title>.+?)\s*$", re.MULTILINE)
#: Marcador de lo que IDATA debe completar antes de entregar: [[plazo de entrega]].
#: No se usan comillas angulares porque en español son comillas legítimas y el
#: detector confundía citas del propio texto con datos pendientes.
_PLACEHOLDER = re.compile(r"\[\[([^\]]*)\]\]")

#: Sin `nl2br`: el texto viene con saltos de línea duros a ~80 columnas y
#: convertirlos en <br> rompería todos los párrafos.
_EXTENSIONS = ["tables", "fenced_code", "sane_lists", "attr_list", "toc"]
_EXTENSION_CONFIGS = {
    # `slugify_unicode` conserva las tildes, así los anclajes del índice escrito a
    # mano ('#1-qué-es-este-servicio') coinciden con los que genera la extensión.
    "toc": {"slugify": slugify_unicode, "permalink": False},
}


@dataclass(frozen=True)
class DocumentMeta:
    title: str
    subtitle: str = ""
    document_type: str = "Documento"
    version: str = ""
    date: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%d-%m-%Y"))
    confidentiality: str = "Documento confidencial · uso exclusivo del destinatario"


def strip_internal_notes(text: str) -> tuple[str, int]:
    """Devuelve (texto_limpio, bloques_eliminados)."""
    cleaned, removed = _INTERNAL_BLOCK.subn("", text)
    return cleaned, removed


def extract_title(text: str) -> str | None:
    match = _H1.search(text)
    return match.group("title").strip() if match else None


def drop_first_h1(text: str) -> str:
    """El H1 va en la portada; repetirlo al inicio del cuerpo es ruido."""
    return _H1.sub("", text, count=1)


def find_placeholders(text: str) -> list[str]:
    """Lo que queda por completar. Se avisa en la CLI antes de entregar, en vez
    de resaltarlo en el PDF del cliente: el objetivo es que IDATA lo note a
    tiempo, no que el destinatario descubra un hueco pintado de amarillo."""
    return sorted({m.group(0) for m in _PLACEHOLDER.finditer(text)})


def markdown_to_html(text: str, *, highlight_placeholders: bool = False) -> str:
    converter = markdown.Markdown(
        extensions=_EXTENSIONS, extension_configs=_EXTENSION_CONFIGS, output_format="html"
    )
    html = converter.convert(text)
    if highlight_placeholders:
        html = _PLACEHOLDER.sub(r'<span class="placeholder">[[\1]]</span>', html)
    return html


def build_document_context(
    source: Path | str,
    *,
    meta: DocumentMeta | None = None,
    include_internal: bool = False,
) -> dict:
    raw = Path(source).read_text(encoding="utf-8")

    removed = 0
    if not include_internal:
        raw, removed = strip_internal_notes(raw)

    title = (meta.title if meta and meta.title else None) or extract_title(raw) or "Documento"
    body = markdown_to_html(drop_first_h1(raw), highlight_placeholders=include_internal)
    resolved = meta or DocumentMeta(title=title)

    return {
        "branding": load_branding(),
        "title": title,
        "subtitle": resolved.subtitle,
        "document_type": resolved.document_type,
        "version": resolved.version,
        "date": resolved.date,
        "confidentiality": resolved.confidentiality,
        "body": body,
        "placeholders": find_placeholders(raw),
        "internal_blocks_removed": removed,
        "internal_included": include_internal,
    }
