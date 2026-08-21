"""Datos estructurados: JSON-LD y microdatos (plan SEO/GEO §6.4).

Compartido por SEO y GEO. Para el buscador, el marcado decide si el resultado
sale enriquecido; para un motor generativo es la diferencia entre deducir de qué
habla la página y saberlo.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import yaml

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.core.crawl import CrawlResult
from idata_sentinel.core.html_parse import json_ld_blocks, schema_nodes, schema_types

_MODULE = "search_visibility"
_DATA = Path(__file__).resolve().parent.parent / "data" / "schema_types.yaml"

_MICRODATA_HINTS = ("itemscope", "itemtype=", "vocab=", "typeof=")


def _catalog() -> dict:
    if not _DATA.exists():
        return {}
    return yaml.safe_load(_DATA.read_text(encoding="utf-8")) or {}


class StructuredDataCheck(BaseCheck):
    id = "structured_data"
    category = "Datos estructurados"
    module = _MODULE

    async def run(self, ctx) -> list[CheckResult]:
        crawl: CrawlResult | None = getattr(ctx, "crawl", None)
        root = crawl.root if crawl else None
        if root is None or not root.html:
            return [self._error_result(
                sub_id="structured_data_unreachable",
                reason="No se obtuvo HTML de la portada para leer los datos estructurados.",
            )]

        html = root.html
        blocks, errors = json_ld_blocks(html)
        types = schema_types(blocks)
        out: list[CheckResult] = []

        if errors:
            out.append(self._result(
                sub_id="structured_data_invalid",
                severity="medium", likelihood="high", status="fail",
                title="Hay datos estructurados que no se pueden leer",
                finding=(
                    f"{len(errors)} bloque(s) JSON-LD tienen JSON malformado: {errors[0]}. "
                    "Un buscador tampoco puede leerlos."
                ),
                business_impact=(
                    "El marcado existe pero no sirve para nada, y como el bloque está en la "
                    "página nadie sospecha que haya un problema."
                ),
                recommendation="Corregir el JSON-LD y validarlo antes de publicar.",
                evidence="; ".join(errors[:2])[:300], references=("schema.org",),
            ))

        has_microdata = any(hint in html.lower() for hint in _MICRODATA_HINTS)
        if not blocks and not has_microdata:
            return [*out, self._result(
                sub_id="structured_data_missing",
                severity="medium", likelihood="high", status="fail",
                title="El sitio no publica datos estructurados",
                finding="No se encontró JSON-LD ni microdatos en la portada.",
                business_impact=(
                    "El buscador y los motores generativos tienen que deducir qué es este "
                    "negocio a partir del texto. Sin marcado no hay resultados enriquecidos ni "
                    "una entidad clara que citar."
                ),
                recommendation=(
                    "Publicar JSON-LD con al menos Organization (o LocalBusiness) y WebSite."
                ),
                evidence="Sin <script type=\"application/ld+json\">", references=("schema.org",),
            )]

        if not _has_any(types, ("Organization", "LocalBusiness", "ProfessionalService", "Person")):
            out.append(self._result(
                sub_id="organization_schema_missing",
                severity="medium", likelihood="high", status="fail",
                title="Sin identidad de la organización en los datos estructurados",
                finding=(
                    f"Hay marcado ({', '.join(sorted(types)) or 'sin @type'}) pero ninguno "
                    "declara quién es el responsable del sitio."
                ),
                business_impact=(
                    "Es lo que ata el sitio a una entidad concreta. Sin eso, un motor "
                    "generativo puede confundir el negocio con otro de nombre parecido."
                ),
                recommendation="Añadir un nodo Organization o LocalBusiness con name, url y logo.",
                evidence=", ".join(sorted(types))[:200], references=("schema.org/Organization",),
            ))

        if not _has_any(types, ("BreadcrumbList",)) and len(crawl.html_pages) > 1:
            out.append(self._result(
                sub_id="breadcrumb_missing",
                severity="low", likelihood="low", status="warning",
                title="Sin migas de pan marcadas",
                finding="No se encontró BreadcrumbList en los datos estructurados.",
                business_impact=(
                    "El resultado de búsqueda muestra la URL cruda en vez de la ruta de "
                    "secciones, y se pierde contexto de dónde está la página dentro del sitio."
                ),
                recommendation="Marcar la navegación jerárquica con BreadcrumbList.",
                evidence=", ".join(sorted(types))[:200], references=("schema.org/BreadcrumbList",),
            ))

        out.extend(self._incomplete_nodes(blocks, types))
        out.extend(self._faq(crawl, types))
        return out

    def _incomplete_nodes(self, blocks: list, types: set[str]) -> list[CheckResult]:
        """Tipos presentes a los que les faltan propiedades requeridas."""
        required = (_catalog().get("required_properties") or {})
        out: list[CheckResult] = []
        for type_name, props in required.items():
            if type_name not in types:
                continue
            for node in schema_nodes(blocks, type_name):
                missing = [p for p in props if not node.get(p)]
                if not missing:
                    continue
                out.append(self._result(
                    sub_id=f"structured_data_incomplete@{type_name}",
                    severity="low", likelihood="medium", status="warning",
                    title=f"El marcado {type_name} está incompleto",
                    finding=f"Al nodo {type_name} le faltan propiedades: {', '.join(missing)}.",
                    business_impact=(
                        "Un marcado incompleto se descarta para los resultados enriquecidos: "
                        "el esfuerzo ya está hecho y no rinde."
                    ),
                    recommendation=f"Completar {', '.join(missing)} en el nodo {type_name}.",
                    evidence=", ".join(missing)[:200], references=(f"schema.org/{type_name}",),
                ))
                break  # un hallazgo por tipo basta; repetirlo por nodo es ruido
        return out

    def _faq(self, crawl: CrawlResult, types: set[str]) -> list[CheckResult]:
        """Contenido en forma de preguntas sin marcado que permita citarlo."""
        if _has_any(types, ("FAQPage", "QAPage", "Question")):
            return []
        from idata_sentinel.core.html_parse import headings

        questions = [
            h.text for page in crawl.html_pages for h in headings(page.html)
            if h.text.strip().endswith("?") or h.text.strip().startswith("¿")
        ]
        if len(questions) < 3:
            return []
        return [self._result(
            sub_id="faq_schema_absent_with_faq_content",
            severity="low", likelihood="medium", status="warning",
            title="Hay preguntas y respuestas sin marcado de FAQ",
            finding=(
                f"Se detectaron {len(questions)} encabezados en forma de pregunta sin marcado "
                f"FAQPage: «{questions[0][:70]}»."
            ),
            business_impact=(
                "El contenido ya está escrito en el formato que un motor generativo prefiere "
                "citar; sin el marcado hay que deducirlo y se pierde la oportunidad."
            ),
            recommendation="Marcar las preguntas frecuentes con FAQPage.",
            evidence="; ".join(questions[:3])[:300], references=("schema.org/FAQPage",),
        )]


def _has_any(types: set[str], wanted: tuple[str, ...]) -> bool:
    lowered = {t.lower() for t in types}
    return any(w.lower() in lowered for w in wanted)


def _path(url: str) -> str:
    return urlparse(url).path or "/"
