"""Runner del módulo Identificación de vulnerabilidades (plan maestro §3)."""
from __future__ import annotations

import asyncio
import logging

from idata_sentinel.core.check_base import CheckResult
from idata_sentinel.core.engine import RunParams
from idata_sentinel.core.robots import RobotsPolicy
from idata_sentinel.modules.vuln_identification.context import ScanContext
from idata_sentinel.modules.vuln_identification.registry import checks_for_mode

logger = logging.getLogger(__name__)


class VulnIdentificationModule:
    name = "vuln_identification"

    async def run(self, params: RunParams) -> list[dict]:
        robots, robots_outcome = await self._fetch_robots(params)
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
            hardening_baseline=authorization.hardening_baseline if authorization else {},
            robots=robots,
        )
        ctx.seed_cache("/robots.txt", robots_outcome)

        checks = checks_for_mode(ctx.mode)
        gathered = await asyncio.gather(*(self._safe_run(c, ctx) for c in checks))

        results: list[CheckResult] = []
        for r in gathered:
            results.extend(r)
        return [r.to_dict() for r in results]

    async def _fetch_robots(self, params: RunParams):
        """El engine ya lo obtiene y lo comparte entre módulos; solo se pide aquí
        si el módulo se ejecuta de forma aislada (tests, uso programático)."""
        if params.robots is not None and params.robots_outcome is not None:
            return params.robots, params.robots_outcome

        await params.rate_limiter.wait(params.host)
        outcome = await params.http.get(f"{params.target.rstrip('/')}/robots.txt")
        policy = (
            RobotsPolicy.from_text(outcome.response.text)
            if outcome.ok and outcome.response.status_code == 200
            else RobotsPolicy.empty()
        )
        return policy, outcome

    async def _safe_run(self, check, ctx: ScanContext) -> list[CheckResult]:
        try:
            return await check.run(ctx)
        except Exception as e:  # red de seguridad: un check nunca tumba el módulo
            logger.exception("check %s crashed", check.id)
            return [check._error_result(
                sub_id=f"{check.id}_error",
                reason=f"Error interno: {type(e).__name__}: {e}",
                evidence=str(e),
            )]
