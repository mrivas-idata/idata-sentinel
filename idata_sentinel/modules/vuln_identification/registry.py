"""Registro explícito de checks del módulo (evita descubrimiento mágico, facilita testing)."""
from __future__ import annotations

from idata_sentinel.checks.auth_enforcement import AuthEnforcementCheck
from idata_sentinel.checks.breach import BreachExposureCheck
from idata_sentinel.checks.cookies import CookiesCheck
from idata_sentinel.checks.cors_config import CorsConfigCheck
from idata_sentinel.checks.exposure import ExposureCheck
from idata_sentinel.checks.http_headers import HttpHeadersCheck
from idata_sentinel.checks.http_methods import HttpMethodsCheck
from idata_sentinel.checks.javascript import JavaScriptCheck
from idata_sentinel.checks.modern_headers import ModernHeadersCheck
from idata_sentinel.checks.redirect_audit import RedirectAuditCheck
from idata_sentinel.checks.security_files import SecurityFilesCheck
from idata_sentinel.checks.tech_fingerprint import TechFingerprintCheck
from idata_sentinel.checks.tls_ssl import TlsSslCheck
from idata_sentinel.core.check_base import BaseCheck, Mode

ALL_CHECKS: list[type[BaseCheck]] = [
    # Pasivos (y expansión de superficie en audit).
    HttpHeadersCheck,
    ModernHeadersCheck,
    TlsSslCheck,
    CookiesCheck,
    TechFingerprintCheck,
    SecurityFilesCheck,
    ExposureCheck,
    JavaScriptCheck,
    # OSINT opt-in: no-op salvo que haya API key configurada (Tier 1.3).
    BreachExposureCheck,
    # Activos: solo corren en audit y con habilitación explícita por nombre (§4).
    HttpMethodsCheck,
    CorsConfigCheck,
    AuthEnforcementCheck,
    RedirectAuditCheck,
]


def checks_for_mode(mode: Mode) -> list[BaseCheck]:
    return [C() for C in ALL_CHECKS if mode in C.modes]


def active_check_ids() -> list[str]:
    """Ids de los checks que ejecutan una técnica activa (requieren habilitación
    explícita por nombre). La CLI los usa para validar `--active-check` y para
    expandir `all` listando el alcance antes de ejecutar."""
    return [getattr(C, "id") for C in ALL_CHECKS if getattr(C, "active", False)]


def checks_for_context(ctx) -> list[BaseCheck]:
    """Checks a ejecutar según el contexto: filtra por modo **y** por el gate de
    activación (plan activo §4.6). Un check activo no habilitado ni se instancia.

    Es el primer filtro; cada check activo además revalida `ctx.active_enabled`
    por dentro (defensa en profundidad), por si se le invoca fuera del runner.
    """
    out: list[BaseCheck] = []
    for cls in ALL_CHECKS:
        if ctx.mode not in cls.modes:
            continue
        check = cls()
        if getattr(check, "active", False) and not ctx.active_enabled(check):
            continue
        out.append(check)
    return out
