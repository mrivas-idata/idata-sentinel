"""Runner del Módulo 5 — Visibilidad en buscadores y motores generativos.

Declara `scoring_domain = "visibility"`: sus hallazgos se puntúan en un eje
propio y **no** entran en el score de seguridad. Mezclarlos produciría un número
sin significado —un sitio con un RCE sin parche mejoraría su nota de seguridad
por tener buenos títulos— (plan SEO/GEO §2).
"""
from __future__ import annotations

import asyncio
import logging

from idata_sentinel.core.check_base import CheckResult
from idata_sentinel.core.crawl import DEFAULT_PAGE_BUDGET, crawl
from idata_sentinel.core.engine import RunParams, VISIBILITY
from idata_sentinel.core.scan_context import ScanContext
from idata_sentinel.modules.search_visibility.registry import checks_for_mode

logger = logging.getLogger(__name__)


class SearchVisibilityModule:
    name = "search_visibility"
    scoring_domain = VISIBILITY

    def __init__(self, *, page_budget: int = DEFAULT_PAGE_BUDGET, field_data: bool = False) -> None:
        self.page_budget = page_budget
        #: Consulta de datos de campo (CrUX). Opt-in explícito: envía la URL del
        #: objetivo a un tercero, así que nunca se activa por omisión (§8.2).
        self.field_data = field_data

    async def run(self, params: RunParams) -> list[dict]:
        ctx = ScanContext(
            target=params.target,
            host=params.host,
            mode=params.mode,  # type: ignore[arg-type]
            http=params.http,
            rate_limiter=params.rate_limiter,
            authorized=params.authorized,
            robots=params.robots,
            interstitial=params.interstitial,
        )
        if params.root_outcome is not None:
            ctx.seed_cache("/", params.root_outcome)
        if params.robots_outcome is not None:
            ctx.seed_cache("/robots.txt", params.robots_outcome)

        # El intersticial anti-bot invalida todo lo que dependa del contenido, y
        # aquí *todo* depende del contenido: lo que respondió no es el sitio.
        if ctx.interstitial is not None:
            return [c._interstitial_result(ctx.interstitial).to_dict() for c in checks_for_mode(ctx.mode)]

        ctx.crawl = await crawl(ctx, budget=self.page_budget)
        ctx.field_data_enabled = self.field_data

        checks = checks_for_mode(ctx.mode)
        gathered = await asyncio.gather(*(self._safe_run(c, ctx) for c in checks))

        results: list[CheckResult] = []
        for group in gathered:
            results.extend(group)
        return [r.to_dict() for r in results]

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
