"""Exposición del dominio en filtraciones conocidas (Tier 1.3) — OSINT opt-in.

Off por defecto: sin `IDATA_HIBP_API_KEY` configurada, no corre ni genera tráfico
(ver `core/breach.py`). Cuando está configurada, reporta cuántas cuentas del
dominio aparecen en brechas conocidas y en cuáles —nunca los correos concretos—.
"""
from __future__ import annotations

import logging

from idata_sentinel.core.breach import BreachProvider, resolve_provider
from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.core.domains import registrable_domain
from idata_sentinel.modules.vuln_identification.context import ScanContext

logger = logging.getLogger(__name__)


class BreachExposureCheck(BaseCheck):
    id = "breach_exposure"
    category = "Filtraciones de datos"
    #: No depende del contenido servido por el objetivo: consulta una base OSINT.
    content_dependent = False
    modes = frozenset({"passive", "audit"})

    def __init__(self, provider: BreachProvider | None = None) -> None:
        # Inyectable para test; en producción se resuelve desde el entorno.
        self._provider = provider
        self._provider_explicit = provider is not None

    async def run(self, ctx: ScanContext) -> list[CheckResult]:
        provider = self._provider if self._provider_explicit else resolve_provider()
        if provider is None:
            return []  # sin API key: no-op, sin tráfico externo

        domain = registrable_domain(ctx.host) or ctx.host
        try:
            summary = await provider.domain_breaches(domain)
        except Exception as e:  # una falla del servicio externo no rompe el escaneo
            logger.info("consulta de filtraciones falló para %s: %s", domain, e)
            return [self._error_result(
                sub_id=f"breach_lookup_unavailable@{domain}",
                reason=f"No se pudo consultar el proveedor de filtraciones: {type(e).__name__}.",
            )]

        if summary is None or summary.account_count == 0:
            return [self._result(
                sub_id=f"breach_none_found@{domain}", severity="info", likelihood="low", status="pass",
                title=f"Sin cuentas de {domain} en filtraciones conocidas",
                finding="El proveedor de filtraciones no reportó cuentas del dominio.",
                business_impact="Evidencia positiva al momento de la consulta.",
                recommendation="Sin acción.", evidence=domain, references=("HIBP",),
            )]

        return [self._result(
            sub_id=f"breached_accounts_exposed@{domain}",
            severity="high", likelihood="high", status="fail",
            title=f"{summary.account_count} cuenta(s) de {domain} en filtraciones conocidas",
            finding=(
                f"{summary.account_count} dirección(es) del dominio aparecen en brechas conocidas: "
                f"{', '.join(summary.breach_names[:8])}"
                + ("…" if len(summary.breach_names) > 8 else "")
                + ". Las credenciales filtradas habilitan credential stuffing y phishing dirigido."
            ),
            business_impact=(
                "Correos corporativos en filtraciones son la materia prima de los ataques de "
                "apropiación de cuentas: reutilización de contraseñas, phishing personalizado y "
                "fraude al negocio. Es una exposición concreta, no hipotética."
            ),
            recommendation=(
                "Forzar reset de contraseñas de las cuentas afectadas, exigir MFA, y monitorear "
                "credential stuffing. Capacitar al personal expuesto sobre phishing dirigido."
            ),
            # Solo nombres públicos de brechas y conteo: nunca los correos.
            evidence=f"{summary.account_count} cuenta(s); brechas: {', '.join(summary.breach_names[:8])}",
            references=("HIBP", "OWASP Credential Stuffing"),
        )]
