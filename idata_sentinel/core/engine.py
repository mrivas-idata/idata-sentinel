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
from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.core.rate_limiter import RateLimiter


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

        results: dict[str, list[dict]] = {}
        artifacts: dict[str, dict] = {}
        async with HttpClient() as http:
            params = RunParams(
                target=request.target,
                host=host,
                mode=mode,
                http=http,
                rate_limiter=self.rate_limiter,
                authorized=authorized,
                authorization=request.authorization,
                dns=DnsResolver(),
            )
            for module in selected:
                output = await module.run(params)
                if isinstance(output, ModuleOutput):
                    results[module.name] = output.findings
                    if output.artifacts:
                        artifacts[module.name] = output.artifacts
                else:
                    results[module.name] = output

        return {
            "target": request.target,
            "mode": mode,
            "modules": results,
            "artifacts": artifacts,
        }
