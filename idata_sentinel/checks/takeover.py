"""Riesgo de subdomain takeover por CNAME colgante (plan maestro §4 — Módulo 2).

**Solo detección.** El plan prohíbe explotar (§0/§1.2): Sentinel nunca reclama,
registra ni ocupa el recurso huérfano — se limita a observar dos señales públicas
y advertir. Reclamarlo sería tomar control de infraestructura ajena.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@lru_cache(maxsize=1)
def _load_signatures() -> list[dict]:
    return yaml.safe_load((_DATA_DIR / "takeover_signatures.yaml").read_text(encoding="utf-8")) or []


@dataclass(frozen=True)
class TakeoverSignal:
    service: str
    cname: str
    reason: str  # "nxdomain" | "unclaimed_page"


def match_service(cnames: tuple[str, ...]) -> tuple[dict, str] | None:
    for cname in cnames:
        normalized = cname.rstrip(".").lower()
        for signature in _load_signatures():
            for suffix in signature.get("cname_suffixes", []):
                if normalized.endswith(suffix.lower()):
                    return signature, normalized
    return None


def evaluate_takeover(
    cnames: tuple[str, ...],
    *,
    cname_resolves: bool,
    body: str = "",
) -> TakeoverSignal | None:
    """Requiere **ambas** condiciones (CNAME a SaaS conocido + destino huérfano)
    para no marcar como riesgo un servicio legítimamente activo."""
    matched = match_service(cnames)
    if matched is None:
        return None
    signature, cname = matched

    if not cname_resolves:
        return TakeoverSignal(service=signature["service"], cname=cname, reason="nxdomain")

    lowered = body.lower()
    for pattern in signature.get("body_patterns", []):
        if pattern.lower() in lowered:
            return TakeoverSignal(service=signature["service"], cname=cname, reason="unclaimed_page")

    return None
