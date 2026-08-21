"""Registro explícito de checks del Módulo 5 (mismo patrón que los demás)."""
from __future__ import annotations

from idata_sentinel.checks.geo_readiness import GeoReadinessCheck
from idata_sentinel.checks.performance import PerformanceCheck
from idata_sentinel.checks.seo_content import SeoContentCheck
from idata_sentinel.checks.seo_indexability import SeoIndexabilityCheck
from idata_sentinel.checks.seo_local import SeoLocalCheck
from idata_sentinel.checks.structured_data import StructuredDataCheck
from idata_sentinel.core.check_base import BaseCheck, Mode

ALL_CHECKS: list[type[BaseCheck]] = [
    SeoIndexabilityCheck,
    SeoContentCheck,
    StructuredDataCheck,
    SeoLocalCheck,
    GeoReadinessCheck,
    PerformanceCheck,
]


def checks_for_mode(mode: Mode) -> list[BaseCheck]:
    return [C() for C in ALL_CHECKS if mode in C.modes]
