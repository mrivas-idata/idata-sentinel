"""Arma el contexto de datos para la plantilla del reporte ejecutivo (plan maestro §8)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

from idata_sentinel.reporting.charts import (
    grade_color,
    severity_color,
    severity_label,
    severity_segments,
    sparkline,
)

_BRANDING_PATH = Path(__file__).resolve().parent.parent / "branding" / "idata.yaml"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Las 4 líneas del plan maestro §0 — se muestran todas aunque el módulo
# correspondiente aún no exista (Fases 3-5), para no rediseñar la plantilla después.
_CANONICAL_MODULES = [
    ("vuln_identification", "Vulnerabilidades"),
    ("asset_inventory", "Activos"),
    ("data_privacy", "Datos Personales"),
    ("monitoring", "Monitoreo"),
]

_GRADE_CLASS = {"A": "primary", "B": "primary", "C": "medium", "D": "high", "F": "critical"}


def _load_branding() -> dict:
    return yaml.safe_load(_BRANDING_PATH.read_text(encoding="utf-8"))


def build_report_context(scan_result: dict, risk: dict, *, report_number: str | None = None) -> dict:
    """scan_result: {"target", "mode", "modules": {module_name: [finding, ...]}}.
    risk: salida de RiskScore.to_dict()."""
    branding = _load_branding()
    modules = scan_result.get("modules", {})
    all_findings = [f for findings in modules.values() for f in findings]
    actionable = sorted(
        (f for f in all_findings if f["status"] in ("fail", "warning")),
        key=lambda f: _SEVERITY_ORDER.get(f["severity"], 5),
    )

    module_summaries = []
    for module_name, label in _CANONICAL_MODULES:
        findings = modules.get(module_name)
        evaluated = findings is not None
        module_summaries.append({
            "name": module_name,
            "label": label,
            "evaluated": evaluated,
            "score": risk["module_scores"].get(module_name) if evaluated else None,
            "finding_count": len([f for f in findings if f["status"] in ("fail", "warning")]) if evaluated else 0,
        })

    severity_counts = {level: 0 for level in _SEVERITY_ORDER}
    for f in actionable:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    return {
        "report_number": report_number or f"IDS-{uuid.uuid4().hex[:8].upper()}",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "target": scan_result["target"],
        "mode": scan_result["mode"],
        "mode_label": "Auditoría autorizada" if scan_result["mode"] == "audit" else "Prospección pasiva",
        "branding": branding,
        "score": risk["score"],
        "grade": risk["grade"],
        "grade_class": _GRADE_CLASS.get(risk["grade"], "info"),
        "module_summaries": module_summaries,
        "top_findings": actionable[:5],
        "all_findings": actionable,
        "total_findings": len(actionable),
        "severity_counts": severity_counts,
        "severity_segments": severity_segments(severity_counts),
        "grade_color": grade_color(risk["grade"]),
        "severity_color": severity_color,
        "severity_label": severity_label,
        "surface_map": _artifact(scan_result, "asset_inventory", "surface_map"),
        "compliance": _artifact(scan_result, "data_privacy", "compliance_21719"),
        "monitoring": _artifact(scan_result, "monitoring", "monitoring"),
        "trend_spark": _trend_spark(scan_result),
    }


def _trend_spark(scan_result: dict):
    """Sparkline de la tendencia, si el Módulo 4 aportó su histórico (§6)."""
    monitoring = _artifact(scan_result, "monitoring", "monitoring") or {}
    points = (monitoring.get("trend") or {}).get("points") or []
    return sparkline([p["score"] for p in points], width=420, height=90) if len(points) > 1 else None


def _artifact(scan_result: dict, module: str, key: str) -> dict | None:
    """Artefacto opcional de un módulo. `None` si ese módulo no corrió, para que
    la sección correspondiente del reporte se degrade con elegancia."""
    return scan_result.get("artifacts", {}).get(module, {}).get(key)
