"""Renderizado del reporte a HTML y PDF (plan maestro §8).

WeasyPrint requiere las librerías nativas de Pango/Cairo/GObject (ver plan de
infraestructura §11.4: se instalan vía apt-get en el Dockerfile de Railway).
En un entorno sin esas librerías (p.ej. Windows sin GTK3 runtime), `render_html`
funciona igual (es solo Jinja2), pero `export_pdf` falla al importar weasyprint —
por eso el import está diferido dentro de la función.
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "jinja2"]),
)


def render_html(context: dict) -> str:
    template = _env.get_template("report.html.jinja2")
    return template.render(**context)


def export_pdf(context: dict, output_path: Path) -> None:
    _write_pdf(render_html(context), output_path)


def render_document_html(context: dict) -> str:
    """Documentos largos en Markdown (guía del cliente, propuestas): mismo motor,
    plantilla distinta. Ver `reporting/document.py`."""
    template = _env.get_template("document.html.jinja2")
    return template.render(**context)


def export_document_pdf(context: dict, output_path: Path) -> None:
    _write_pdf(render_document_html(context), output_path)


def _write_pdf(html_str: str, output_path: Path) -> None:
    from weasyprint import HTML  # noqa: PLC0415 — import diferido, ver docstring del módulo

    HTML(string=html_str).write_pdf(str(output_path))
