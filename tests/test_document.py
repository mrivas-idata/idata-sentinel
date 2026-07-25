from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from idata_sentinel.interfaces.cli import app
from idata_sentinel.reporting.document import (
    DocumentMeta,
    build_document_context,
    drop_first_h1,
    extract_title,
    find_placeholders,
    markdown_to_html,
    strip_internal_notes,
)
from idata_sentinel.reporting.pdf_export import render_document_html

runner = CliRunner()

GUIDE = Path("docs/guia_cliente.md")

_SAMPLE = """# Título del documento

Un párrafo con **negrita** y `código`.

<!-- interno:inicio -->
> Nota que no debe llegar al cliente.
<!-- interno:fin -->

## Una sección

| Columna | Otra |
|---|---|
| dato | dato |

- viñeta uno
- viñeta dos

Falta completar [[el plazo]] y también [[el responsable]].
"""


@pytest.fixture
def source(tmp_path) -> Path:
    path = tmp_path / "documento.md"
    path.write_text(_SAMPLE, encoding="utf-8")
    return path


# -- funciones puras -------------------------------------------------------


def test_strip_internal_notes_removes_the_block_and_counts_it():
    cleaned, removed = strip_internal_notes(_SAMPLE)
    assert removed == 1
    assert "no debe llegar al cliente" not in cleaned
    assert "Una sección" in cleaned


def test_strip_internal_notes_is_a_noop_without_markers():
    cleaned, removed = strip_internal_notes("# Sin marcadores")
    assert removed == 0
    assert cleaned == "# Sin marcadores"


def test_extract_title_takes_the_first_h1():
    assert extract_title(_SAMPLE) == "Título del documento"
    assert extract_title("Sin encabezado") is None


def test_drop_first_h1_only_removes_one():
    text = "# Uno\n\ntexto\n\n# Dos\n"
    result = drop_first_h1(text)
    assert "# Uno" not in result
    assert "# Dos" in result


def test_find_placeholders_deduplicates_and_sorts():
    assert find_placeholders("[[b]] y [[a]] y otra vez [[a]]") == ["[[a]]", "[[b]]"]


def test_angle_quotes_are_not_placeholders():
    """En español « » son comillas legítimas, no marcadores de dato pendiente."""
    assert find_placeholders("La sección «Lo que no hace» explica los límites.") == []


def test_markdown_converts_tables_lists_and_emphasis():
    html = markdown_to_html(_SAMPLE)
    assert "<table>" in html
    assert "<strong>negrita</strong>" in html
    assert "<code>código</code>" in html
    assert html.count("<li>") == 2


def test_headings_get_unicode_anchors():
    """El índice escrito a mano enlaza con tildes; los anclajes deben coincidir."""
    html = markdown_to_html("## Qué es este servicio")
    assert 'id="qué-es-este-servicio"' in html


def test_hard_wrapped_paragraphs_stay_together():
    """Sin `nl2br`: un párrafo cortado a 80 columnas es un solo párrafo."""
    html = markdown_to_html("una línea\ncortada en dos\n")
    assert "<br" not in html
    assert html.count("<p>") == 1


def test_placeholders_highlighted_only_on_request():
    assert 'class="placeholder"' not in markdown_to_html("[[dato]]")
    assert 'class="placeholder"' in markdown_to_html("[[dato]]", highlight_placeholders=True)


# -- contexto --------------------------------------------------------------


def test_context_defaults_the_title_to_the_first_h1(source):
    assert build_document_context(source)["title"] == "Título del documento"


def test_explicit_meta_wins_over_the_h1(source):
    context = build_document_context(
        source, meta=DocumentMeta(title="Otro título", subtitle="Bajada", version="2.0")
    )
    assert context["title"] == "Otro título"
    assert context["subtitle"] == "Bajada"
    assert context["version"] == "2.0"


def test_client_copy_drops_internal_notes(source):
    context = build_document_context(source)
    assert context["internal_blocks_removed"] == 1
    assert context["internal_included"] is False
    assert "no debe llegar al cliente" not in context["body"]


def test_internal_copy_keeps_the_notes(source):
    context = build_document_context(source, include_internal=True)
    assert context["internal_blocks_removed"] == 0
    assert "no debe llegar al cliente" in context["body"]


def test_pending_data_is_reported(source):
    assert build_document_context(source)["placeholders"] == ["[[el plazo]]", "[[el responsable]]"]


def test_title_is_not_repeated_in_the_body(source):
    assert "<h1>Título del documento</h1>" not in build_document_context(source)["body"]


# -- render ----------------------------------------------------------------


def test_render_produces_a_branded_document(source):
    html = render_document_html(build_document_context(source))
    assert "IDATA Chile" in html
    assert 'class="cover"' in html
    assert "<table>" in html


def test_body_html_is_not_double_escaped(source):
    """El cuerpo ya es HTML; escaparlo lo mostraría como texto plano."""
    html = render_document_html(build_document_context(source))
    assert "<strong>negrita</strong>" in html
    assert "&lt;strong&gt;" not in html


def test_internal_copy_carries_a_visible_warning(source):
    html = render_document_html(build_document_context(source, include_internal=True))
    assert "Copia interna" in html
    assert "No lo entregue al cliente" in html


def test_client_copy_has_no_internal_warning(source):
    assert "Copia interna" not in render_document_html(build_document_context(source))


def test_internal_links_get_page_numbers_in_print():
    html = render_document_html(build_document_context(GUIDE))
    assert "target-counter(attr(href), page)" in html


# -- la guía real ----------------------------------------------------------


def test_the_client_guide_renders_completely():
    context = build_document_context(GUIDE)
    html = render_document_html(context)

    assert context["internal_blocks_removed"] == 1
    for fragment in ("Formulario de autorización", "Checklist de preparación", "Glosario",
                     "Qué verá en sus registros", "Responsables del encargo"):
        assert fragment in html, fragment


def test_the_client_guide_hides_internal_notes():
    html = render_document_html(build_document_context(GUIDE))
    assert "nota interna para IDATA" not in html
    assert "con-notas-internas" not in html


def test_the_guide_declares_the_attack_like_paths():
    """Anexo D debe declarar /.env y /.git/HEAD: son firmas clásicas de ataque
    y omitirlas destruiría la credibilidad del documento ante el SOC."""
    html = render_document_html(build_document_context(GUIDE))
    assert "/.env" in html
    assert "/.git/HEAD" in html


def test_the_guide_still_has_data_to_complete():
    """Recordatorio activo: si algún día queda en cero, es que se completó."""
    assert build_document_context(GUIDE)["placeholders"]


# -- CLI -------------------------------------------------------------------


def test_doc_command_writes_html(tmp_path, source):
    out = tmp_path / "salida.html"
    result = runner.invoke(app, ["doc", str(source), "--html", str(out)])

    assert result.exit_code == 0
    assert out.exists()
    assert "IDATA Chile" in out.read_text(encoding="utf-8")


def test_doc_command_lists_pending_data(tmp_path, source):
    out = tmp_path / "salida.html"
    result = runner.invoke(app, ["doc", str(source), "--html", str(out)])

    assert "Faltan 2 dato(s)" in result.stdout
    assert "el plazo" in result.stdout  # los corchetes no deben ser tragados por Rich


def test_doc_command_reports_removed_internal_blocks(tmp_path, source):
    out = tmp_path / "salida.html"
    result = runner.invoke(app, ["doc", str(source), "--html", str(out)])
    assert "1 bloque(s) de notas internas eliminado" in result.stdout


def test_doc_command_warns_on_the_internal_copy(tmp_path, source):
    out = tmp_path / "salida.html"
    result = runner.invoke(
        app, ["doc", str(source), "--html", str(out), "--con-notas-internas"]
    )
    assert "No la entregues" in result.stdout


def test_doc_command_rejects_a_missing_file(tmp_path):
    result = runner.invoke(app, ["doc", str(tmp_path / "no-existe.md"), "--html", "x.html"])
    assert result.exit_code == 1
    assert "No existe el archivo" in result.stdout


def test_doc_command_requires_an_output(source):
    result = runner.invoke(app, ["doc", str(source)])
    assert result.exit_code == 1
    assert "al menos --pdf o --html" in result.stdout


@pytest.mark.integration
def test_export_guide_pdf(tmp_path):
    """Requiere las nativas de WeasyPrint; corre en la imagen Docker y en CI."""
    from idata_sentinel.reporting.pdf_export import export_document_pdf

    output = tmp_path / "guia.pdf"
    export_document_pdf(build_document_context(GUIDE), output)
    assert output.stat().st_size > 20_000
