"""Orquestador de módulos y checks (plan maestro §2).

No conoce el `ScanContext` específico de ningún módulo: le pasa a cada
módulo registrado un `RunParams` genérico, y cada módulo construye su
propio contexto enriquecido a partir de eso. Esto evita que `core/`
dependa de `modules/`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from urllib.parse import urlparse

from idata_sentinel.core.authorization import AuthorizationGate, AuthorizationRequest
from idata_sentinel.core.dns_resolver import DnsResolver
from idata_sentinel.core.http_client import FetchOutcome, HttpClient
from idata_sentinel.core.rate_limiter import RateLimiter
from idata_sentinel.core.robots import RobotsPolicy


@dataclass
class RunParams:
    target: str
    host: str
    mode: str  # "passive" | "audit"
    http: HttpClient
    rate_limiter: RateLimiter
    authorized: bool
    authorization: AuthorizationRequest | None
    dns: DnsResolver | None = None
    #: `robots.txt` se obtiene una sola vez en el engine y se comparte: es la
    #: política del modo pasivo y varios módulos la necesitan.
    robots: RobotsPolicy | None = None
    robots_outcome: FetchOutcome | None = None
    #: Hallazgos de los módulos ya ejecutados. El Módulo 3 los necesita para
    #: mapear la seguridad del tratamiento (evidenciada por el Módulo 1) al
    #: checklist de la Ley 21.719.
    previous_findings: list[dict] = field(default_factory=list)
    #: Artefactos de los módulos ya ejecutados. El Módulo 4 compara el mapa de
    #: superficie actual (Módulo 2) contra el de la línea base.
    module_artifacts: dict = field(default_factory=dict)


@dataclass
class ModuleOutput:
    """Salida enriquecida de un módulo.

    Existe porque el Módulo 2 produce, además de hallazgos, un **inventario de
    activos** (plan maestro §4) que el reporte necesita como tabla/mapa y que no
    cabe en el contrato de check. Los módulos que solo emiten hallazgos pueden
    seguir devolviendo `list[dict]` — el engine normaliza ambas formas.
    """

    findings: list[dict]
    artifacts: dict = field(default_factory=dict)


@runtime_checkable
class ScanModule(Protocol):
    name: str

    async def run(self, params: RunParams) -> "list[dict] | ModuleOutput": ...


#: Orden de ejecución. El Módulo 3 va último porque su checklist de cumplimiento
#: consume los hallazgos de los anteriores.
DEFAULT_MODULE_ORDER = {
    "vuln_identification": 10,
    "asset_inventory": 20,
    "data_privacy": 30,
    "monitoring": 40,
}


@dataclass
class ScanRequest:
    target: str
    mode: str = "passive"
    modules: list[str] | None = None  # None = todos los módulos registrados
    authorization: AuthorizationRequest | None = None
    source_ip: str = "unknown"


class Engine:
    def __init__(self, *, rate_limit_seconds: float = 2.0) -> None:
        self._modules: dict[str, ScanModule] = {}
        self.rate_limiter = RateLimiter(min_interval=rate_limit_seconds)
        self.authorization_gate = AuthorizationGate()

    def register_module(self, module: ScanModule) -> None:
        self._modules[module.name] = module

    async def scan(self, request: ScanRequest) -> dict:
        mode = request.mode
        authorized = False

        if mode == "audit":
            if request.authorization is None:
                mode = "passive"  # sin datos de autorización, nunca corre activo
            else:
                authorized = self.authorization_gate.authorize(
                    request.authorization, source_ip=request.source_ip
                )
                if not authorized:
                    mode = "passive"  # degradar, nunca abortar sin dejar registro

        host = urlparse(request.target).hostname or request.target

        selected = (
            list(self._modules.values())
            if not request.modules
            else [self._modules[m] for m in request.modules if m in self._modules]
        )
        selected.sort(key=lambda m: DEFAULT_MODULE_ORDER.get(m.name, 50))

        results: dict[str, list[dict]] = {}
        artifacts: dict[str, dict] = {}
        accumulated: list[dict] = []

        async with HttpClient() as http:
            robots, robots_outcome = await self._fetch_robots(request.target, host, http)
            params = RunParams(
                target=request.target,
                host=host,
                mode=mode,
                http=http,
                rate_limiter=self.rate_limiter,
                authorized=authorized,
                authorization=request.authorization,
                dns=DnsResolver(),
                robots=robots,
                robots_outcome=robots_outcome,
            )
            for module in selected:
                params.previous_findings = list(accumulated)
                params.module_artifacts = dict(artifacts)
                output = await module.run(params)
                findings = output.findings if isinstance(output, ModuleOutput) else output
                results[module.name] = findings
                accumulated.extend(findings)
                if isinstance(output, ModuleOutput) and output.artifacts:
                    artifacts[module.name] = output.artifacts

        return {
            "target": request.target,
            "mode": mode,
            "modules": results,
            "artifacts": artifacts,
        }

    async def _fetch_robots(
        self, target: str, host: str, http: HttpClient
    ) -> tuple[RobotsPolicy, FetchOutcome]:
        await self.rate_limiter.wait(host)
        outcome = await http.get(f"{target.rstrip('/')}/robots.txt")
        policy = (
            RobotsPolicy.from_text(outcome.response.text)
            if outcome.ok and outcome.response.status_code == 200
            else RobotsPolicy.empty()
        )
        return policy, outcome
