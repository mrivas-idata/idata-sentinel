"""Runner del módulo Identificación de vulnerabilidades (plan maestro §3)."""
from __future__ import annotations

import asyncio
import logging

from idata_sentinel.core.check_base import CheckResult
from idata_sentinel.core.engine import RunParams
from idata_sentinel.core.robots import RobotsPolicy
from idata_sentinel.modules.vuln_identification.context import ScanContext
from idata_sentinel.modules.vuln_identification.registry import checks_for_context

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
            interstitial=params.interstitial,
            active_checks=params.active_checks,
            active_acknowledged=params.active_acknowledged,
            client_session=params.client_session,
        )
        ctx.seed_cache("/robots.txt", robots_outcome)
        if params.root_outcome is not None:
            ctx.seed_cache("/", params.root_outcome)

        baseline_invalid = self._compile_baseline(ctx)

        checks = checks_for_context(ctx)
        gathered = await asyncio.gather(*(self._safe_run(c, ctx) for c in checks))

        results: list[CheckResult] = []
        if ctx.interstitial is not None:
            results.append(self._interstitial_notice(ctx))
        if baseline_invalid is not None:
            results.append(baseline_invalid)
        for r in gathered:
            results.extend(r)
        return [r.to_dict() for r in results]

    def _compile_baseline(self, ctx: ScanContext) -> CheckResult | None:
        """Compila el baseline del cliente una sola vez y lo cachea en el contexto.

        Si el baseline está malformado, la comparación se omite por completo —nunca
        se inventan mismatches a partir de un baseline roto— y se emite un único
        `baseline_invalid` no evaluable. Devuelve ese hallazgo, o `None` si todo ok.
        """
        if not ctx.hardening_baseline:
            return None
        from idata_sentinel.core.baseline import BaselineError, HardeningBaseline

        try:
            ctx._compiled_baseline = HardeningBaseline.load(ctx.hardening_baseline)
            return None
        except BaselineError as e:
            ctx._compiled_baseline = None
            ctx.hardening_baseline = {}  # los checks ya no intentan compararlo
            return CheckResult(
                id=f"baseline_invalid@{ctx.host}",
                module=self.name, category="Baseline de hardening",
                severity="info", likelihood="low", status="info", confidence="unverified",
                title="El baseline de hardening acordado no se pudo interpretar",
                finding=(
                    f"El baseline entregado por el cliente no es válido: {e}. La comparación "
                    f"contra baseline se omitió en este escaneo; el resto del diagnóstico corre igual."
                ),
                business_impact="No se pudo medir la configuración contra el estándar acordado.",
                recommendation="Corregir el formato del baseline (ver data/baseline.schema.yaml) y reescanear.",
                evidence=str(e), references=("baseline",),
            )

    def _interstitial_notice(self, ctx: ScanContext) -> CheckResult:
        """Aviso único y visible de que el escaneo no vio el sitio.

        Va en el Módulo 1 porque es el primero que corre: el operador tiene que
        leerlo antes que cualquier otro hallazgo. `severity="info"` y
        `confidence="unverified"` para que no altere el score — no es un
        problema del objetivo, es una limitación de la medición.
        """
        signal = ctx.interstitial
        return CheckResult(
            id=f"scan_blocked_by_interstitial@{ctx.host}",
            module=self.name,
            category="Cobertura del escaneo",
            severity="info",
            likelihood="low",
            status="warning",
            title="El sitio no pudo evaluarse: hay una página de verificación anti-bot delante",
            finding=(
                f"{signal.summary} Los checks que dependen del contenido o de las cabeceras de "
                f"la aplicación quedaron sin ejecutar, porque habrían descrito la página de "
                f"verificación y no el sitio. Lo que sí es válido en este escaneo: TLS, DNS, "
                f"correo e inventario de activos, que no dependen del contenido servido."
            ),
            business_impact=(
                "Este informe no describe la postura del sitio. Entregarlo como si lo hiciera "
                "afirmaría cosas falsas sobre el objetivo. Que exista la protección anti-bot es, "
                "en sí mismo, una señal positiva de la defensa perimetral."
            ),
            recommendation=(
                "Para diagnosticar el contenido hace falta modo auditoría con autorización del "
                "cliente y que este incluya en lista blanca al escáner. IDATA Sentinel no resuelve "
                "ni evade el desafío anti-bot: hacerlo sería evasión, prohibida en ambos modos."
            ),
            evidence=signal.evidence,
            references=("OWASP WSTG-INFO",),
            confidence="unverified",
        )

    async def _safe_run(self, check, ctx: ScanContext) -> list[CheckResult]:
        if ctx.interstitial is not None and check.content_dependent:
            return [check._interstitial_result(ctx.interstitial)]
        try:
            return await check.run(ctx)
        except Exception as e:  # red de seguridad: un check nunca tumba el módulo
            logger.exception("check %s crashed", check.id)
            return [check._error_result(
                sub_id=f"{check.id}_error",
                reason=f"Error interno: {type(e).__name__}: {e}",
                evidence=str(e),
            )]

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
