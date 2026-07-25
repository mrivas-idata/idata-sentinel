"""Registro explícito de checks del módulo (evita descubrimiento mágico, facilita testing)."""
from __future__ import annotations

from idata_sentinel.checks.cookies import CookiesCheck
from idata_sentinel.checks.exposure import ExposureCheck
from idata_sentinel.checks.http_headers import HttpHeadersCheck
from idata_sentinel.checks.modern_headers import ModernHeadersCheck
from idata_sentinel.checks.security_files import SecurityFilesCheck
from idata_sentinel.checks.tech_fingerprint import TechFingerprintCheck
from idata_sentinel.checks.tls_ssl import TlsSslCheck
from idata_sentinel.core.check_base import BaseCheck, Mode

ALL_CHECKS: list[type[BaseCheck]] = [
    HttpHeadersCheck,
    ModernHeadersCheck,
    TlsSslCheck,
    CookiesCheck,
    TechFingerprintCheck,
    SecurityFilesCheck,
    ExposureCheck,
]


def checks_for_mode(mode: Mode) -> list[BaseCheck]:
    return [C() for C in ALL_CHECKS if mode in C.modes]
