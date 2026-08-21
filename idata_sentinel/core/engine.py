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
from idata_sentinel.core.interstitial import InterstitialSignal, detect_interstitial
from idata_sentinel.core.rate_limiter import RateLimiter
from idata_sentinel.core.robots import RobotsPolicy
from idata_sentinel.core.session import ClientSession


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
    #: La raíz también se pide una sola vez: la necesitan el Módulo 1 y el 3, y
    #: es donde se detecta el intersticial anti-bot que decide si el contenido
    #: observado es siquiera el del objetivo.
    root_outcome: FetchOutcome | None = None
    interstitial: InterstitialSignal | None = None
    #: Gate de activación de capacidades activas (plan activo §4) y sesión
    #: provista por el cliente (§7). Defaults seguros: nada activo, sin sesión.
    active_checks: frozenset[str] = field(default_factory=frozenset)
    active_acknowledged: bool = False
    client_session: ClientSession | None = None
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


#: Ejes de puntuación. Un módulo pertenece a uno y solo a uno, y los ejes se
#: puntúan por separado: promediar riesgo de seguridad con visibilidad en
#: buscadores produciría un número que no significa nada —un sitio con un RCE
#: sin parche mejoraría su nota de seguridad por tener buenos `title`—.
SECURITY = "security"
VISIBILITY = "visibility"


@runtime_checkable
class ScanModule(Protocol):
    name: str
    #: Eje al que pertenecen los hallazgos del módulo. Los módulos que no lo
    #: declaran son de seguridad, que es lo que eran los cuatro originales: así
    #: el score de todo el histórico se mantiene idéntico.
    scoring_domain: str

    async def run(self, params: RunParams) -> "list[dict] | ModuleOutput": ...


def module_domain(module: object) -> str:
    return getattr(module, "scoring_domain", SECURITY)


#: Orden de ejecución. El Módulo 3 va último porque su checklist de cumplimiento
#: consume los hallazgos de los anteriores.
DEFAULT_MODULE_ORDER = {
    "vuln_identification": 10,
    "asset_inventory": 20,
    "data_privacy": 30,
    "monitoring": 40,
    "search_visibility": 50,
}


@dataclass
class ScanRequest:
    target: str
    mode: str = "passive"
    modules: list[str] | None = None  # None = todos los módulos registrados
    authorization: AuthorizationRequest | None = None
    source_ip: str = "unknown"
    #: Capacidades activas pedidas por nombre (plan activo §4). Vacío = ninguna:
    #: el modo audit sin esto solo expande superficie, no ejecuta técnicas activas.
    active_checks: frozenset[str] = field(default_factory=frozenset)
    active_acknowledged: bool = False  # doble confirmación (--i-understand-active)
    client_session: ClientSession | None = None  # sesión provista (§7)


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
                    request.authorization,
                    source_ip=request.source_ip,
                    active_context=self._active_context(request),
                )
                if not authorized:
                    mode = "passive"  # degradar, nunca abortar sin dejar registro

        # Defensa en profundidad: si no quedó como audit autorizado, ninguna
        # capacidad activa ni sesión sobrevive — el modo pasivo jamás las ve.
        active_checks = request.active_checks if (mode == "audit" and authorized) else frozenset()
        active_acknowledged = request.active_acknowledged if (mode == "audit" and authorized) else False
        client_session = request.client_session if (mode == "audit" and authorized) else None

        host = urlparse(request.target).hostname or request.target

        selected = (
            list(self._modules.values())
            if not request.modules
            else [self._modules[m] for m in request.modules if m in self._modules]
        )
        selected.sort(key=lambda m: DEFAULT_MODULE_ORDER.get(m.name, 50))

        results: dict[str, list[dict]] = {}
        by_domain: dict[str, dict[str, list[dict]]] = {}
        artifacts: dict[str, dict] = {}
        accumulated: list[dict] = []

        async with HttpClient() as http:
            robots, robots_outcome = await self._fetch_robots(request.target, host, http)
            root_outcome = await self._fetch_root(request.target, host, http)
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
                root_outcome=root_outcome,
                interstitial=detect_interstitial(root_outcome.response),
                active_checks=active_checks,
                active_acknowledged=active_acknowledged,
                client_session=client_session,
            )
            for module in selected:
                params.previous_findings = list(accumulated)
                params.module_artifacts = dict(artifacts)
                output = await module.run(params)
                findings = output.findings if isinstance(output, ModuleOutput) else output
                results[module.name] = findings
                by_domain.setdefault(module_domain(module), {})[module.name] = findings
                accumulated.extend(findings)
                if isinstance(output, ModuleOutput) and output.artifacts:
                    artifacts[module.name] = output.artifacts

        return {
            "target": request.target,
            "mode": mode,
            "modules": results,
            # Los hallazgos otra vez, agrupados por eje de puntuación. `modules`
            # se mantiene tal cual para no romper a ningún consumidor existente.
            "modules_by_domain": by_domain,
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

    async def _fetch_root(self, target: str, host: str, http: HttpClient) -> FetchOutcome:
        await self.rate_limiter.wait(host)
        return await http.get(target, follow_redirects=True)

    @staticmethod
    def _active_context(request: ScanRequest) -> dict:
        """Contexto activo para el `audit_log`: qué técnicas se pidieron, si se
        confirmaron y si hubo sesión. Nunca incluye el material de la sesión."""
        return {
            "active_checks_enabled": sorted(request.active_checks),
            "active_acknowledged": request.active_acknowledged,
            "authenticated_scan": request.client_session is not None,
        }
