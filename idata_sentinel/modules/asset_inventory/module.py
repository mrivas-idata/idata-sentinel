"""Runner del Módulo 2 — Inventario de activos tecnológicos (plan maestro §4).

Flujo: descubrir (CT logs) → perfilar cada activo (DNS + un único GET) →
evaluar → correlacionar en el mapa de superficie de ataque.

Cada activo se toca **una sola vez** en red y pasa por el rate limiter, que es
por-host: perfilar 25 subdominios en paralelo no viola el límite de ≥2 s por
dominio del modo pasivo (§1.2).
"""
from __future__ import annotations

import asyncio
import logging

from idata_sentinel.checks.asset_exposure import AssetExposureCheck, SubdomainTakeoverCheck
from idata_sentinel.checks.cloud_waf import detect_providers, leaked_origin
from idata_sentinel.checks.dns_email import DnsEmailCheck
from idata_sentinel.checks.subdomains import (
    CRT_SH_ATTEMPTS,
    CRT_SH_BACKOFF_SECONDS,
    DiscoveryResult,
    discover_subdomains,
)
from idata_sentinel.checks.takeover import evaluate_takeover
from idata_sentinel.checks.tech_fingerprint import detect_technologies
from idata_sentinel.core.check_base import CheckResult
from idata_sentinel.core.dns_resolver import DnsResolver
from idata_sentinel.core.engine import ModuleOutput, RunParams
from idata_sentinel.modules.asset_inventory.context import (
    AssetInventoryContext,
    AssetProfile,
    extract_title,
)
from idata_sentinel.modules.asset_inventory.surface import build_surface_map

logger = logging.getLogger(__name__)

_BODY_SNIPPET_BYTES = 8000


class AssetInventoryModule:
    name = "asset_inventory"

    def __init__(
        self,
        *,
        max_assets: int = 25,
        discovery_attempts: int = CRT_SH_ATTEMPTS,
        discovery_backoff: float = CRT_SH_BACKOFF_SECONDS,
    ) -> None:
        self.max_assets = max_assets
        # Inyectables para que los tests ejerciten la ruta de fallo sin dormir:
        # con los valores por defecto, cinco tests sumaban 31 s de espera pura.
        self.discovery_attempts = discovery_attempts
        self.discovery_backoff = discovery_backoff

    async def run(self, params: RunParams) -> ModuleOutput:
        ctx = self._build_context(params)
        discovered, discovery = await self._discover(ctx)

        profiles = await asyncio.gather(
            *(self._safe_profile(ctx, host, source) for host, source in discovered)
        )

        findings: list[CheckResult] = []
        takeover_check = SubdomainTakeoverCheck()
        exposure_check = AssetExposureCheck()
        for profile in profiles:
            findings.extend(takeover_check.evaluate(profile))
            findings.extend(exposure_check.evaluate(profile))

        findings.extend(await self._apex_findings(ctx, profiles))

        surface = build_surface_map(list(profiles), apex=ctx.apex)
        surface["discovery_complete"] = discovery.complete
        surface["discovery_sources"] = [
            {"name": s.name, "ok": s.ok, "count": s.count, "reason": s.reason}
            for s in discovery.sources
        ]
        surface["discovery_truncated"] = discovery.truncated
        surface["discovery_total_known"] = discovery.total_known
        if not discovery.complete:
            findings.append(self._degraded_discovery(ctx, discovery))
        findings.append(self._summary(surface, ctx, discovery))

        return ModuleOutput(
            findings=[f.to_dict() for f in findings],
            artifacts={"surface_map": surface},
        )

    # -- contexto y descubrimiento ------------------------------------------

    def _build_context(self, params: RunParams) -> AssetInventoryContext:
        authorization = params.authorization
        allowed = authorization.allowed_domains if authorization and params.authorized else ()
        extra = authorization.additional_assets if authorization and params.authorized else ()
        return AssetInventoryContext(
            target=params.target,
            host=params.host,
            mode=params.mode,  # type: ignore[arg-type]
            http=params.http,
            rate_limiter=params.rate_limiter,
            dns=params.dns or DnsResolver(),
            authorized=params.authorized,
            allowed_domains=allowed,
            additional_assets=extra,
            max_assets=self.max_assets,
        )

    async def _discover(
        self, ctx: AssetInventoryContext
    ) -> tuple[list[tuple[str, str]], DiscoveryResult]:
        """El host objetivo siempre entra. Los subdominios salen de CT logs; los
        activos del cliente solo se aceptan dentro del scope autorizado (§1.1)."""
        ordered: dict[str, str] = {ctx.host: "target"}

        try:
            discovery = await discover_subdomains(
                ctx.http,
                ctx.host,
                limit=ctx.max_assets,
                attempts=self.discovery_attempts,
                backoff=self.discovery_backoff,
            )
        except Exception as e:  # el descubrimiento nunca puede tumbar el módulo
            logger.exception("descubrimiento de subdominios falló para %s", ctx.host)
            discovery = DiscoveryResult([], ok=False, reason=f"error interno: {type(e).__name__}")

        for host in discovery.hosts:
            ordered.setdefault(host, discovery.host_sources.get(host, "CT logs"))

        for host in ctx.additional_assets:
            host = host.strip().lower().rstrip(".")
            if host and ctx.in_scope(host):
                ordered[host] = "client"

        return list(ordered.items())[: ctx.max_assets], discovery

    def _degraded_discovery(self, ctx: AssetInventoryContext, discovery) -> CheckResult:
        """Se emite también cuando *parte* de las fuentes respondió.

        Un inventario construido con un registro caído sigue siendo útil, pero
        presentarlo como exhaustivo es lo que hacía que el cliente leyera "1
        activo" y creyera que esa era toda su superficie.
        """
        responded = [s.name for s in discovery.sources if s.ok]
        finding = (
            f"Ningún registro de Certificate Transparency respondió: {discovery.reason}. "
            f"El inventario de este escaneo puede estar incompleto."
            if not responded
            else (
                f"Se consultaron {len(discovery.sources)} registros de Certificate Transparency "
                f"y respondió {', '.join(responded)}; falló {discovery.reason}. El inventario es "
                f"utilizable pero no puede presentarse como exhaustivo."
            )
        )
        return self._check_helper()._result(
            sub_id=f"asset_discovery_incomplete@{ctx.host}",
            severity="info", likelihood="low", status="warning",
            title="El descubrimiento de subdominios no pudo completarse",
            finding=finding,
            business_impact=(
                "Un inventario parcial da una falsa sensación de superficie reducida. "
                "Los activos no descubiertos son precisamente los que nadie vigila."
            ),
            recommendation=(
                "Repetir el escaneo más tarde. Si el problema persiste, aportar el listado "
                "de subdominios conocidos para completar el inventario manualmente."
            ),
            evidence="; ".join(
                f"{s.name}: {'ok, ' + str(s.count) + ' nombre(s)' if s.ok else s.reason}"
                for s in discovery.sources
            ),
            references=("CIS Control 1",),
        )

    @staticmethod
    def _check_helper() -> AssetExposureCheck:
        return AssetExposureCheck()

    # -- perfilado -----------------------------------------------------------

    async def _safe_profile(
        self, ctx: AssetInventoryContext, host: str, source: str
    ) -> AssetProfile:
        try:
            return await self._profile(ctx, host, source)
        except Exception:  # un activo problemático no invalida el inventario
            logger.exception("perfilado de %s falló", host)
            return AssetProfile(host=host, source=source)

    async def _profile(
        self, ctx: AssetInventoryContext, host: str, source: str
    ) -> AssetProfile:
        records = await ctx.dns.records_for(host)
        profile = AssetProfile(host=host, source=source, dns=records)

        if records.resolves:
            scheme, response = await self._probe(ctx, host)
            if response is not None:
                set_cookies = tuple(response.headers.get_list("set-cookie"))
                profile.reachable = True
                profile.scheme = scheme
                profile.status_code = response.status_code
                profile.server = response.headers.get("server")
                profile.set_cookies = set_cookies
                profile.body_snippet = self._body_of(response)
                profile.title = extract_title(profile.body_snippet)
                profile.technologies = tuple(detect_technologies(response))
                profile.cloud = detect_providers(
                    response.headers, set_cookies=set_cookies, cnames=profile.cnames
                )
                profile.origin_leak = leaked_origin(response.headers)

        profile.takeover = evaluate_takeover(
            profile.cnames, cname_resolves=records.resolves, body=profile.body_snippet
        )
        return profile

    async def _probe(self, ctx: AssetInventoryContext, host: str):
        """HTTPS primero; HTTP solo como fallback, para poder distinguir
        'no responde' de 'responde pero sin TLS'."""
        for scheme in ("https", "http"):
            await ctx.rate_limiter.wait(host)
            outcome = await ctx.http.get(f"{scheme}://{host}/", follow_redirects=True)
            if outcome.ok:
                return scheme, outcome.response
        return None, None

    @staticmethod
    def _body_of(response) -> str:
        content_type = response.headers.get("content-type", "")
        if content_type and not content_type.startswith(("text/", "application/json", "application/xml")):
            return ""
        try:
            return response.text[:_BODY_SNIPPET_BYTES]
        except (UnicodeDecodeError, ValueError):
            return ""

    # -- hallazgos de dominio ------------------------------------------------

    async def _apex_findings(
        self, ctx: AssetInventoryContext, profiles: tuple[AssetProfile, ...]
    ) -> list[CheckResult]:
        """Evalúa SPF, DMARC, MTA-STS, CAA y DNSSEC sobre el **dominio
        registrable**, no sobre el host del objetivo.

        Escanear `https://www.cliente.cl` hacía que se consultara
        `_dmarc.www.cliente.cl`, que por definición no existe: se reportaba
        "falta DMARC" en un dominio que sí lo publica, y la recomendación pedía
        publicarlo en el lugar equivocado.
        """
        apex_host = ctx.apex
        check = DnsEmailCheck()

        profile = next((p for p in profiles if p.host == apex_host), None)
        records = profile.dns if profile is not None else None
        try:
            if records is None:
                # El apex puede no estar entre los perfiles si el descubrimiento
                # falló: se resuelve aparte antes que renunciar a evaluarlo.
                records = await ctx.dns.records_for(apex_host)
            return await check.evaluate(apex_host, records, ctx.dns)
        except Exception as e:
            logger.exception("DnsEmailCheck falló para %s", apex_host)
            return [check._error_result(
                sub_id=f"dns_email_error@{apex_host}",
                reason=f"Error interno: {type(e).__name__}: {e}",
                evidence=str(e),
            )]

    def _summary(self, surface: dict, ctx: AssetInventoryContext, discovery) -> CheckResult:
        totals = surface["totals"]
        exposure = surface["exposure_summary"]
        check = AssetExposureCheck()
        # El tope de activos a perfilar es una decisión nuestra de coste, no una
        # medida de la superficie del cliente. Callarlo repetía el mismo engaño
        # que motivó la segunda fuente: presentar un recorte como el total.
        truncated = (
            f" Los registros de CT conocen {discovery.total_known} nombre(s) bajo el dominio; "
            f"se perfilaron los {len(discovery.hosts)} más relevantes por el tope de este escaneo, "
            f"así que la superficie real es mayor que la inventariada aquí."
            if discovery.truncated
            else ""
        )
        return check._result(
            sub_id=f"attack_surface_summary@{ctx.host}",
            severity="info", likelihood="low", status="info",
            title=f"Superficie de ataque de {ctx.host}: {totals['reachable']} activo(s) accesible(s)",
            finding=(
                f"Se inventariaron {totals['discovered']} activo(s): {totals['resolving']} resuelven en DNS, "
                f"{totals['reachable']} responden por web ({totals['https']} sobre HTTPS). "
                f"{totals['distinct_ips']} IP(s) y {totals['distinct_technologies']} tecnología(s) distintas."
                f"{truncated}"
            ),
            business_impact=(
                "Cada activo accesible es una puerta potencial. Conocer el inventario completo es "
                "el requisito previo a cualquier control: no se protege lo que no se sabe que existe."
            ),
            recommendation=(
                "Validar que todos los activos listados sean conocidos y necesarios; "
                "retirar de Internet los que no lo sean."
            ),
            evidence=(
                f"No productivos expuestos: {len(exposure['non_production'])}; "
                f"sin HTTPS: {len(exposure['without_https'])}; "
                f"riesgo de takeover: {len(exposure['takeover_risk'])}; "
                f"sin CDN/WAF: {len(exposure['without_cdn_or_waf'])}"
            ),
            references=("CIS Control 1",),
        )
