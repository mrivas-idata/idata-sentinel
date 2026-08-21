"""SEO local: negocios con presencia física o área de servicio (plan SEO/GEO §6.3).

Es lo de mayor retorno inmediato para la cartera típica de IDATA —estudios
jurídicos, salud, servicios profesionales—, donde la búsqueda local decide la
mayoría de los contactos y la competencia se juega en un radio de kilómetros.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.core.crawl import CrawlResult
from idata_sentinel.core.html_parse import (
    json_ld_blocks,
    meta_content,
    schema_nodes,
    schema_types,
    title_of,
    visible_text,
)

_MODULE = "search_visibility"
_DATA = Path(__file__).resolve().parent.parent / "data" / "schema_types.yaml"

_LOCAL_TYPES = ("LocalBusiness", "ProfessionalService", "MedicalBusiness", "Store", "Organization")

#: Teléfono chileno en cualquiera de sus formas usuales de escritura.
_PHONE = re.compile(r"(?:\+?56[\s.-]?)?(?:\(?\d{1,2}\)?[\s.-]?)?\d{4}[\s.-]?\d{4}")
_TEL_LINK = re.compile(r"href\s*=\s*[\"']tel:", re.IGNORECASE)
#: Señales de dirección postal chilena en texto corrido.
_ADDRESS_HINT = re.compile(
    r"\b(av(?:enida)?|calle|pasaje|camino|carretera)\b[^.,;]{3,60}?\b\d{1,5}\b",
    re.IGNORECASE,
)


def _catalog() -> dict:
    if not _DATA.exists():
        return {}
    return yaml.safe_load(_DATA.read_text(encoding="utf-8")) or {}


class SeoLocalCheck(BaseCheck):
    id = "seo_local"
    category = "SEO local"
    module = _MODULE

    async def run(self, ctx) -> list[CheckResult]:
        crawl: CrawlResult | None = getattr(ctx, "crawl", None)
        root = crawl.root if crawl else None
        if root is None or not root.html:
            return [self._error_result(
                sub_id="seo_local_unreachable",
                reason="No se obtuvo HTML de la portada para evaluar el SEO local.",
            )]

        html = root.html
        blocks, _ = json_ld_blocks(html)
        types = schema_types(blocks)
        text = visible_text(html)

        out: list[CheckResult] = []
        local_nodes = [n for t in _LOCAL_TYPES for n in schema_nodes(blocks, t)]
        has_local_schema = any(
            t.lower() in {x.lower() for x in _LOCAL_TYPES[:4]} for t in types
        )

        expected = self._expected_types(html)
        if not has_local_schema and expected:
            out.append(self._result(
                sub_id="local_business_schema_missing",
                severity="medium", likelihood="high", status="fail",
                title="El negocio no está marcado como negocio local",
                finding=(
                    f"Por el contenido de la portada, este sitio parece de tipo "
                    f"{' / '.join(expected)}, pero no publica ese marcado."
                ),
                business_impact=(
                    "Sin marcado de negocio local no se puede aparecer con dirección, horario y "
                    "teléfono en los resultados, ni ser recomendado con seguridad cuando alguien "
                    "busca el servicio «cerca de mí»."
                ),
                recommendation=(
                    f"Publicar JSON-LD de tipo {expected[0]} con name, address, telephone, "
                    "openingHours y areaServed."
                ),
                evidence=", ".join(sorted(types))[:200] or "sin datos estructurados",
                references=("schema.org/LocalBusiness",),
            ))

        # -- teléfono ---------------------------------------------------------
        phone_in_text = bool(_PHONE.search(text))
        if phone_in_text and not _TEL_LINK.search(html):
            out.append(self._result(
                sub_id="phone_not_linked",
                severity="low", likelihood="high", status="warning",
                title="El teléfono no es pulsable desde el móvil",
                finding="Hay un teléfono en el texto pero ningún enlace `tel:` en la página.",
                business_impact=(
                    "En móvil —de donde viene la mayoría del tráfico local— el usuario tiene que "
                    "copiar el número a mano. Cada paso extra pierde contactos."
                ),
                recommendation="Envolver el teléfono en <a href=\"tel:+56...\">.",
                evidence=(_PHONE.search(text).group(0) if phone_in_text else "")[:60],
                references=(),
            ))

        # -- dirección --------------------------------------------------------
        address_in_text = bool(_ADDRESS_HINT.search(text))
        has_postal = bool(schema_nodes(blocks, "PostalAddress")) or any(
            n.get("address") for n in local_nodes
        )
        if address_in_text and not has_postal:
            out.append(self._result(
                sub_id="address_not_marked_up",
                severity="low", likelihood="medium", status="warning", confidence="medium",
                title="La dirección aparece como texto suelto",
                finding=(
                    "Se detecta lo que parece una dirección en el texto, pero no hay "
                    "`PostalAddress` en los datos estructurados."
                ),
                business_impact=(
                    "El buscador tiene que interpretar la dirección del texto, con riesgo de "
                    "ubicar mal el negocio o no asociarlo a su ficha local."
                ),
                recommendation="Marcar la dirección con PostalAddress dentro del nodo del negocio.",
                evidence=(_ADDRESS_HINT.search(text).group(0) if address_in_text else "")[:120],
                references=("schema.org/PostalAddress",),
            ))

        # -- horario y área de servicio ---------------------------------------
        if local_nodes and not any(n.get("openingHours") or n.get("openingHoursSpecification") for n in local_nodes):
            out.append(self._result(
                sub_id="opening_hours_missing",
                severity="low", likelihood="low", status="warning",
                title="Sin horario de atención declarado",
                finding="El nodo del negocio no declara openingHours.",
                business_impact=(
                    "El resultado de búsqueda no puede mostrar si está abierto ahora, que es la "
                    "señal que más decide un contacto inmediato."
                ),
                recommendation="Declarar openingHours en el marcado del negocio.",
                evidence="Sin openingHours", references=("schema.org/openingHours",),
            ))

        if local_nodes and not any(n.get("areaServed") for n in local_nodes):
            out.append(self._result(
                sub_id="service_area_undeclared",
                severity="low", likelihood="low", status="warning",
                title="Sin área de servicio declarada",
                finding="El nodo del negocio no declara areaServed.",
                business_impact=(
                    "Un servicio que atiende varias comunas o regiones aparece solo asociado a "
                    "su dirección, y pierde las búsquedas del resto de su área real."
                ),
                recommendation="Declarar areaServed con las comunas o regiones que se atienden.",
                evidence="Sin areaServed", references=("schema.org/areaServed",),
            ))

        out.extend(self._nap_consistency(crawl))
        return out

    def _expected_types(self, html: str) -> list[str]:
        """Tipos esperados según el giro que insinúan título y descripción."""
        haystack = " ".join(
            filter(None, [title_of(html), meta_content(html, name="description")])
        ).lower()
        for spec in (_catalog().get("business_hints") or {}).values():
            if any(k.lower() in haystack for k in spec.get("keywords", [])):
                return list(spec.get("expected", []))
        return []

    def _nap_consistency(self, crawl: CrawlResult) -> list[CheckResult]:
        """El mismo teléfono en todas las páginas donde aparezca.

        Un número distinto por página es la causa más común de que una ficha
        local no consolide: el buscador no puede decidir cuál es el bueno.
        """
        numbers: dict[str, set[str]] = {}
        for page in crawl.html_pages:
            for match in _PHONE.finditer(visible_text(page.html)):
                digits = re.sub(r"\D", "", match.group(0))[-8:]
                if len(digits) == 8:
                    numbers.setdefault(digits, set()).add(page.url)

        if len(numbers) <= 1:
            return []
        return [self._result(
            sub_id="nap_inconsistent",
            severity="low", likelihood="medium", status="warning", confidence="medium",
            title="Aparecen varios teléfonos distintos en el sitio",
            finding=(
                f"Se detectaron {len(numbers)} números diferentes entre las páginas analizadas. "
                "Puede ser legítimo (sucursales), pero también es la causa más habitual de que "
                "una ficha local no consolide."
            ),
            business_impact=(
                "Si el buscador no puede decidir cuál es el teléfono oficial, la ficha del "
                "negocio pierde confianza y puede no mostrarse con el dato de contacto."
            ),
            recommendation="Usar un teléfono principal consistente, o marcar cada sede por separado.",
            evidence="; ".join(sorted(numbers)[:4]), references=(),
        )]
