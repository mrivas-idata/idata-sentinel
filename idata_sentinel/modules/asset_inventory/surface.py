"""Correlación: perfiles de activos → mapa de superficie de ataque (plan maestro §4).

El §4 pide explícitamente "activos + tecnología + riesgo asociado". Este módulo
produce esa correlación como artefacto estructurado que consumen tanto el reporte
(sección 5) como la salida JSON (§9.3).
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from idata_sentinel.modules.asset_inventory.context import AssetProfile, is_non_production


def _index(pairs: Iterable[tuple[str, str]]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for key, host in pairs:
        if host not in grouped[key]:
            grouped[key].append(host)
    return dict(sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0])))


def build_surface_map(profiles: list[AssetProfile], *, apex: str) -> dict:
    reachable = [p for p in profiles if p.reachable]

    technology_index = _index(
        (label, p.host) for p in profiles for label in p.technology_labels()
    )
    provider_index = {
        "cdn": _index((name, p.host) for p in profiles for name in p.cloud.cdn),
        "waf": _index((name, p.host) for p in profiles for name in p.cloud.waf),
        "cloud": _index((name, p.host) for p in profiles for name in p.cloud.cloud),
    }
    ip_index = _index((ip, p.host) for p in profiles for ip in p.ips)

    exposure = {
        "non_production": [p.host for p in reachable if is_non_production(p.host)],
        "without_https": [p.host for p in reachable if p.scheme == "http"],
        "takeover_risk": [p.host for p in profiles if p.takeover],
        "without_cdn_or_waf": [
            p.host for p in reachable if not p.cloud.cdn and not p.cloud.waf
        ],
        "origin_leak": [p.host for p in reachable if p.origin_leak],
    }

    return {
        "apex": apex,
        "totals": {
            "discovered": len(profiles),
            "resolving": sum(1 for p in profiles if p.resolves),
            "reachable": len(reachable),
            "https": sum(1 for p in reachable if p.https),
            "distinct_ips": len(ip_index),
            "distinct_technologies": len(technology_index),
        },
        "assets": [p.to_dict() for p in profiles],
        "technology_index": technology_index,
        "provider_index": provider_index,
        "ip_index": ip_index,
        "exposure_summary": exposure,
    }
