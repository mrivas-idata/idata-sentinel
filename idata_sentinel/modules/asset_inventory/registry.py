"""Registro explícito de los checks del Módulo 2.

A diferencia del Módulo 1, estos checks no se ejecutan vía `run(ctx)`: el runner
los invoca con el `AssetProfile` ya perfilado (una sola pasada de red por activo).
El registro existe para documentación, la sección de ayuda y los tests de contrato.
"""
from __future__ import annotations

from idata_sentinel.checks.asset_exposure import AssetExposureCheck, SubdomainTakeoverCheck
from idata_sentinel.checks.dns_email import DnsEmailCheck
from idata_sentinel.core.check_base import BaseCheck

ALL_CHECKS: list[type[BaseCheck]] = [
    DnsEmailCheck,
    SubdomainTakeoverCheck,
    AssetExposureCheck,
]
