"""Runner del Módulo 3 — Datos Personales / Ley 21.719 (plan maestro §5).

El checklist de cumplimiento se construye con los hallazgos de **todos** los
módulos, no solo los propios: el principio de seguridad del tratamiento se
evidencia en el TLS y las cabeceras que evalúa el Módulo 1. Por eso el engine le
entrega los resultados previos vía `RunParams.previous_findings`.
"""
from __future__ import annotations

import asyncio
import logging

from idata_sentinel.core.check_base import CheckResult
from idata_sentinel.core.engine import ModuleOutput, RunParams
from idata_sentinel.core.robots import RobotsPolicy
from idata_sentinel.core.scan_context import ScanContext
from idata_sentinel.modules.data_privacy.compliance import build_compliance_checklist
from idata_sentinel.modules.data_privacy.registry import checks_for_mode

logger = logging.getLogger(__name__)


class DataPrivacyModule:
    name = "data_privacy"

    async def run(self, params: RunParams) -> ModuleOutput:
        authorization = params.authorization
        ctx = ScanContext(
            target=params.target,
            host=params.host,
            mode=params.mode,  # type: ignore[arg-type]
            http=params.http,
            rate_limiter=params.rate_limiter,
            authorized=params.authorized,
            audit_paths=authorization.audit_paths if authorization else (),
            audit_endpoints=authorization.audit_endpoints if authorization else (),
            robots=params.robots or RobotsPolicy.empty(),
            interstitial=params.interstitial,
        )
        if params.root_outcome is not None:
            ctx.seed_cache("/", params.root_outcome)

        checks = checks_for_mode(ctx.mode)
        gathered = await asyncio.gather(*(self._safe_run(c, ctx) for c in checks))

        results: list[CheckResult] = []
        for group in gathered:
            results.extend(group)

        findings = [r.to_dict() for r in results]
        checklist = build_compliance_checklist([*params.previous_findings, *findings])
        return ModuleOutput(findings=findings, artifacts={"compliance_21719": checklist})

    async def _safe_run(self, check, ctx: ScanContext) -> list[CheckResult]:
        # Todo el Módulo 3 se deduce del HTML: formularios, banner de
        # consentimiento, enlace a la política. Sobre una página de verificación
        # anti-bot los tres checks fallarían en falso a la vez, y
        # `privacy_policy_missing` es severidad `high` — el peor hallazgo falso
        # posible para mandarle a un prospecto.
        if ctx.interstitial is not None and check.content_dependent:
            return [check._interstitial_result(ctx.interstitial)]
        try:
            return await check.run(ctx)
        except Exception as e:  # un check nunca tumba el módulo
            logger.exception("check %s crashed", check.id)
            return [check._error_result(
                sub_id=f"{check.id}_error",
                reason=f"Error interno: {type(e).__name__}: {e}",
                evidence=str(e),
            )]
