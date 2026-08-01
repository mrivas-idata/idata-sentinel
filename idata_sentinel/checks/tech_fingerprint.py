"""Fingerprint + CVEs informativas (plan_implementacion_escaneo_vulnerabilidades.md §2.4).

Fingerprint por firmas propias (headers/HTML/meta generator), sin depender de
python-Wappalyzer, per el fallback que autoriza el plan maestro §2.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.modules.vuln_identification.context import ScanContext

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@dataclass(frozen=True)
class Detection:
    product: str
    version: str | None
    #: "tech" para el stack base (CMS, servidor); "plugin"/"theme" para los
    #: componentes de WordPress. Los componentes son donde viven la mayoría de
    #: los CVEs de un sitio WP, y el CMS por sí solo no los revela.
    kind: str = "tech"


#: `/wp-content/plugins|themes/<slug>/...?ver=<x.y[.z]>` en el HTML ya descargado.
#: Se exige `major.minor` (al menos un punto) a propósito: los temas cachean con
#: enteros gigantes tipo `?ver=801499924`, que son cache-busters, no versiones.
#: Tratarlos como versión produciría un "componente vX" falso.
_WP_COMPONENT_RE = re.compile(
    r"/wp-content/(plugins|themes)/([a-z0-9][a-z0-9._-]*)/[^\"'>\s]*?[?&]ver=(\d+(?:\.\d+)+)",
    re.IGNORECASE,
)


def detect_components(resp) -> list[Detection]:
    """Plugins y temas de WordPress con versión, leídos del HTML raíz.

    Cero coste de red: parsea la respuesta que el fingerprint ya tiene. Cuando
    un mismo componente aparece con varias versiones (assets de distintos
    orígenes), se reporta la **más alta** — es la más probable de estar instalada
    y la más conservadora para el cruce con CVE (menos CVEs abiertos)."""
    best: dict[tuple[str, str], tuple[int, ...]] = {}
    for match in _WP_COMPONENT_RE.finditer(resp.text or ""):
        kind = "plugin" if match.group(1).lower() == "plugins" else "theme"
        slug = match.group(2).lower()
        version = match.group(3)
        key = (kind, slug)
        current = best.get(key)
        candidate = _version_tuple(version)
        if current is None or candidate > current:
            best[key] = candidate

    detections: list[Detection] = []
    for (kind, slug), version_t in sorted(best.items()):
        detections.append(
            Detection(product=slug, version=".".join(str(p) for p in version_t), kind=kind)
        )
    return detections


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) or (0,)


def _in_range(version: tuple[int, ...], min_v: tuple[int, ...], max_v: tuple[int, ...] | None) -> bool:
    if version < min_v:
        return False
    if max_v is not None and version >= max_v:
        return False
    return True


@lru_cache(maxsize=1)
def _load_fingerprints() -> list[dict]:
    path = _DATA_DIR / "fingerprints.yaml"
    if not path.exists():
        return []
    return yaml.safe_load(path.read_text(encoding="utf-8")) or []


@lru_cache(maxsize=1)
def _load_cve_hints() -> list[dict]:
    path = _DATA_DIR / "cve_hints.yaml"
    if not path.exists():
        return []
    return yaml.safe_load(path.read_text(encoding="utf-8")) or []


def _severity_from_cvss(label: str) -> str:
    # Degradado a máx. "medium": es informativo, nunca verificado (plan §2.4).
    return {"critical": "medium", "high": "medium", "medium": "low", "low": "low"}.get(label, "low")


def detect_technologies(resp) -> list[Detection]:
    """Detección por firmas, reutilizable fuera de este check (p.ej. por
    Módulo 2 — Inventario de activos — para fingerprint por subdominio)."""
    body = resp.text
    headers = resp.headers
    detections: list[Detection] = []

    for sig in _load_fingerprints():
        product = sig["product"]
        version: str | None = None
        matched = False

        header_name = sig.get("header")
        if header_name:
            value = headers.get(header_name, "")
            if value:
                m = re.search(sig.get("header_pattern", ""), value, re.IGNORECASE)
                if m:
                    matched = True
                    if m.groups():
                        version = m.group(1)

        for pattern in sig.get("html_patterns", []):
            if pattern in body:
                matched = True

        generator = sig.get("meta_generator")
        if generator and generator.lower() in body.lower():
            matched = True

        version_pattern = sig.get("version_pattern")
        if matched and version_pattern and not version:
            m = re.search(version_pattern, body)
            if m and m.groups():
                version = m.group(1)

        if matched:
            detections.append(Detection(product=product, version=version))

    return detections


class TechFingerprintCheck(BaseCheck):
    id = "tech_fingerprint"
    category = "Fingerprint"
    modes = frozenset({"passive", "audit"})

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        outcome = await ctx.get_outcome("/")
        if not outcome.ok:
            return [self._error_result(
                sub_id="tech_fingerprint_unreachable",
                reason="No se pudo obtener la página raíz para fingerprinting.",
            )]

        out: list[CheckResult] = []
        for detection in detect_technologies(outcome.response):
            out.extend(self._result_for_detection(detection))
        for component in detect_components(outcome.response):
            out.extend(self._result_for_component(component))
        return out

    def _result_for_component(self, d: Detection) -> list[CheckResult]:
        """Un plugin/tema de WordPress con versión expuesta. La versión de un
        componente es más accionable que la del CMS: es lo que un atacante cruza
        contra CVEs de ese plugin concreto."""
        kind_label = "plugin" if d.kind == "plugin" else "tema"
        out = [self._result(
            sub_id=f"component_version_disclosure@{d.kind}:{d.product}",
            severity="low", likelihood="medium", status="warning",
            title=f"Componente WordPress ({kind_label}) con versión expuesta: {d.product} {d.version}",
            finding=(
                f"El {kind_label} de WordPress '{d.product}' expone públicamente su versión "
                f"{d.version} en las rutas de recursos del sitio."
            ),
            business_impact=(
                "Los plugins y temas concentran la mayoría de las vulnerabilidades conocidas de "
                "un WordPress. Publicar su versión exacta permite a un atacante buscar CVEs "
                "específicas de ese componente sin tocar el sitio."
            ),
            recommendation=(
                f"Mantener '{d.product}' actualizado y, si es posible, quitar el parámetro de "
                f"versión de las URLs de recursos."
            ),
            evidence=f"wp-content/{d.kind}s/{d.product}/…?ver={d.version}", references=("CWE-200",),
        )]
        out.extend(self._cve_informational(d))
        return out

    def _result_for_detection(self, d: Detection) -> list[CheckResult]:
        out: list[CheckResult] = []
        if d.version:
            out.append(self._result(
                sub_id=f"tech_version_disclosure@{d.product}", severity="low", likelihood="medium",
                status="warning", title=f"Versión de {d.product} expuesta",
                finding=f"Se detectó {d.product} versión {d.version}.",
                business_impact="Facilita el reconocimiento dirigido de vulnerabilidades conocidas.",
                recommendation=f"Ocultar la versión de {d.product} expuesta públicamente.",
                evidence=f"{d.product} {d.version}", references=("CWE-200",),
            ))
            out.extend(self._cve_informational(d))
        else:
            out.append(self._result(
                sub_id=f"tech_detected@{d.product}", severity="info", likelihood="low", status="info",
                title=f"Tecnología detectada: {d.product}",
                finding=f"Se detectó {d.product} (sin versión expuesta).",
                business_impact="Inventario informativo; sin hallazgo de seguridad.",
                recommendation="N/A.", evidence=d.product, references=(),
            ))
        return out

    def _cve_informational(self, d: Detection) -> list[CheckResult]:
        if not d.version:
            return []
        version_t = _version_tuple(d.version)
        out: list[CheckResult] = []
        for entry in _load_cve_hints():
            # Coincidencia por producto/slug, sin distinguir mayúsculas: las
            # entradas de componentes se curan con el slug ("revslider"), las de
            # stack con el nombre ("WordPress").
            if str(entry.get("product", "")).lower() != d.product.lower():
                continue
            min_v = _version_tuple(str(entry.get("min_version", "0")))
            max_raw = entry.get("max_version")
            max_v = _version_tuple(str(max_raw)) if max_raw else None
            if not _in_range(version_t, min_v, max_v):
                continue

            cve_ids = entry.get("cve_ids", [])
            out.append(self._result(
                sub_id=f"cve_informational@{d.product}:{d.version}",
                severity=_severity_from_cvss(entry.get("cvss_severity", "low")),
                likelihood="low",  # fijo: no se verificó explotabilidad (plan §2.4)
                status="info",
                title=f"Posibles CVEs conocidas para {d.product} {d.version}",
                finding=(
                    f"Versión potencialmente afectada por CVEs conocidas ({', '.join(cve_ids)}). "
                    "Hallazgo informativo, no verificado; IDATA Sentinel no comprueba explotabilidad."
                ),
                business_impact=entry.get("title", "Ver referencias CVE."),
                recommendation=f"Actualizar {d.product} a una versión parchada.",
                evidence=f"{d.product} {d.version}", references=tuple(cve_ids),
            ))
        return out
