"""Runner del Módulo 4 — Monitoreo continuo (plan maestro §6).

A diferencia de los otros módulos, este **no escanea**: compara el escaneo en
curso contra la línea base almacenada y reporta lo que cambió. Por eso corre
último y consume `RunParams.previous_findings`.

Convierte un diagnóstico puntual en servicio recurrente: lo valioso no es el
hallazgo, sino que aparezca uno nuevo entre dos fotos.
"""
from __future__ import annotations

import asyncio
import logging

from idata_sentinel.core.check_base import BaseCheck, CheckResult
from idata_sentinel.core.engine import ModuleOutput, RunParams
from idata_sentinel.modules.monitoring.alerts import Notifier, build_alerts, dispatch
from idata_sentinel.modules.monitoring.diff import build_trend, diff_assets, diff_findings
from idata_sentinel.storage.db import ScanStore

logger = logging.getLogger(__name__)

_CERT_EXPIRY_IDS = ("cert_expiring_soon", "cert_expired")


class _MonitoringCheck(BaseCheck):
    """Solo aporta los helpers de construcción de `CheckResult`; el diff lo hace
    el módulo, que es quien tiene acceso al almacén."""

    id = "monitoring"
    category = "Monitoreo"
    module = "monitoring"

    async def run(self, ctx) -> list[CheckResult]:  # pragma: no cover - no aplica
        raise NotImplementedError("El monitoreo se ejecuta desde MonitoringModule.run().")


class MonitoringModule:
    name = "monitoring"

    def __init__(
        self,
        store: ScanStore | None = None,
        *,
        notifiers: list[Notifier] | None = None,
    ) -> None:
        self.store = store or ScanStore()
        self.notifiers = notifiers or []
        self._check = _MonitoringCheck()

    async def run(self, params: RunParams) -> ModuleOutput:
        target = params.target
        current = params.previous_findings

        baseline = await asyncio.to_thread(self.store.baseline, target)
        # El "anterior" es el último escaneo registrado (la corrida previa). La
        # detección de cambios se hace contra ÉL, no contra la línea base: de otro
        # modo un hallazgo que apareció hace tres corridas y sigue ahí se re-anuncia
        # —y re-alerta— en cada escaneo, y el cliente deja de leer las alertas.
        previous = await asyncio.to_thread(self.store.latest_scan, target)
        history = await asyncio.to_thread(self.store.history, target)

        if baseline is None or previous is None:
            return ModuleOutput(
                findings=[self._no_baseline(target).to_dict()],
                artifacts={"monitoring": {
                    "baseline": None,
                    "trend": build_trend(history),
                    "findings_diff": None,
                    "assets_diff": None,
                    "alerts": [],
                }},
            )

        findings_diff = diff_findings(previous.findings, current)
        assets_diff = diff_assets(previous.surface_map(), self._current_surface(params))
        trend = build_trend(history)

        alerts = build_alerts(
            target=target,
            findings_diff=findings_diff,
            assets_diff=assets_diff,
            trend=trend,
            expiring_certs=[f for f in current if f["id"].split("@")[0] in _CERT_EXPIRY_IDS],
        )
        if self.notifiers and alerts:
            await dispatch(alerts, self.notifiers, target=target, trend=trend)

        results = self._results_for(target, previous, findings_diff, assets_diff, trend)
        return ModuleOutput(
            findings=[r.to_dict() for r in results],
            artifacts={"monitoring": {
                "baseline": {"id": baseline.id, "scanned_at": baseline.scanned_at, "score": baseline.score},
                "previous": {"id": previous.id, "scanned_at": previous.scanned_at, "score": previous.score},
                "trend": trend,
                "findings_diff": findings_diff.to_dict(),
                "assets_diff": assets_diff.to_dict(),
                "alerts": [a.to_dict() for a in alerts],
            }},
        )

    @staticmethod
    def _current_surface(params: RunParams) -> dict | None:
        return (params.module_artifacts or {}).get("asset_inventory", {}).get("surface_map")

    def _no_baseline(self, target: str) -> CheckResult:
        return self._check._result(
            sub_id=f"monitoring_baseline_created@{target}",
            severity="info", likelihood="low", status="info",
            title="Línea base establecida",
            finding=(
                f"Es el primer escaneo registrado de {target}: queda como línea base para "
                f"detectar cambios en los próximos escaneos."
            ),
            business_impact=(
                "Aún no hay comparación posible. El valor del monitoreo aparece desde el "
                "segundo escaneo, cuando se puede distinguir lo nuevo de lo conocido."
            ),
            recommendation="Programar re-escaneos con 'idata-sentinel monitor add'.",
            evidence="", references=("CIS Control 1",),
        )

    def _results_for(self, target, previous, findings_diff, assets_diff, trend) -> list[CheckResult]:
        out: list[CheckResult] = []

        for finding in findings_diff.new:
            severity = finding["severity"]
            out.append(self._check._result(
                sub_id=f"new_finding_since_last_scan@{finding['id']}",
                severity=severity if severity != "info" else "low",
                likelihood="medium",
                status="fail" if severity in ("critical", "high", "medium") else "warning",
                title=f"Hallazgo nuevo desde el escaneo anterior: {finding['title']}",
                finding=(
                    f"'{finding['title']}' no existía en el escaneo anterior del {previous.scanned_at[:10]} "
                    f"y aparece ahora."
                ),
                business_impact=(
                    "Un hallazgo nuevo suele venir de un cambio reciente (despliegue, proveedor, "
                    "configuración). Es el momento más barato de corregirlo."
                ),
                recommendation=finding.get("recommendation", "Revisar el hallazgo original."),
                evidence=f"id: {finding['id']}; severidad: {severity}",
                references=("Monitoreo continuo",),
            ))

        for change in findings_diff.severity_changes:
            if not change.worsened:
                continue
            out.append(self._check._result(
                sub_id=f"finding_worsened@{change.id}",
                severity=change.after, likelihood="medium", status="fail",
                title=f"Hallazgo agravado: {change.title}",
                finding=f"La severidad pasó de {change.before} a {change.after} desde la línea base.",
                business_impact="La exposición del activo creció sin que mediara un hallazgo nuevo.",
                recommendation="Revisar qué cambió en la configuración del activo desde el último escaneo.",
                evidence=f"{change.before} -> {change.after}", references=("Monitoreo continuo",),
            ))

        if assets_diff.new_assets:
            out.append(self._check._result(
                sub_id=f"new_assets_detected@{target}",
                severity="medium", likelihood="medium", status="fail",
                title=f"{len(assets_diff.new_assets)} activo(s) nuevo(s) en la superficie de ataque",
                finding=f"Aparecieron activos que no existían en la línea base: {', '.join(assets_diff.new_assets[:10])}.",
                business_impact=(
                    "Superficie de ataque que nadie declaró. Los activos que aparecen sin proceso "
                    "formal suelen ser los que quedan sin parchar."
                ),
                recommendation="Confirmar que cada activo nuevo es conocido, necesario y está bajo control.",
                evidence=", ".join(assets_diff.new_assets)[:400], references=("CIS Control 1",),
            ))

        for host, change in assets_diff.technology_changes.items():
            if not change["added"]:
                continue
            out.append(self._check._result(
                sub_id=f"technology_changed@{host}",
                severity="low", likelihood="low", status="warning",
                title=f"Cambio de tecnología en {host}",
                finding=f"Tecnologías nuevas: {', '.join(change['added'])}"
                        + (f"; ya no observadas: {', '.join(change['removed'])}" if change["removed"] else ""),
                business_impact="Un cambio de stack puede reintroducir configuraciones inseguras.",
                recommendation="Verificar que el cambio fue planificado y que el hardening se mantuvo.",
                evidence=str(change)[:300], references=("Monitoreo continuo",),
            ))

        if findings_diff.resolved:
            out.append(self._check._result(
                sub_id=f"findings_resolved@{target}",
                severity="info", likelihood="low", status="pass",
                title=f"{len(findings_diff.resolved)} hallazgo(s) resuelto(s) desde el escaneo anterior",
                finding="Ya no se observan: "
                        + ", ".join(f["title"] for f in findings_diff.resolved[:10]),
                business_impact="Evidencia objetiva de mejora para reportar a la dirección.",
                recommendation="Mantener el control aplicado y verificarlo en el próximo escaneo.",
                evidence=", ".join(f["id"] for f in findings_diff.resolved)[:400],
                references=("Monitoreo continuo",),
            ))

        delta = trend.get("delta", 0)
        if delta <= -10:
            out.append(self._check._result(
                sub_id=f"risk_score_dropped@{target}",
                severity="medium", likelihood="high", status="fail",
                title=f"El score de riesgo cayó {abs(delta)} puntos",
                finding=f"Score anterior: {trend.get('previous')}; actual: {trend.get('current')}.",
                business_impact="La postura de seguridad se degradó de forma medible entre dos escaneos.",
                recommendation="Revisar los hallazgos nuevos listados en este mismo reporte.",
                evidence=f"delta: {delta}", references=("Monitoreo continuo",),
            ))

        if not out:
            out.append(self._check._result(
                sub_id=f"no_changes_since_last_scan@{target}",
                severity="info", likelihood="low", status="pass",
                title="Sin cambios respecto del escaneo anterior",
                finding=f"No se detectaron hallazgos nuevos ni activos nuevos desde el {previous.scanned_at[:10]}.",
                business_impact="La postura de seguridad se mantiene estable.",
                recommendation="Mantener la cadencia de monitoreo.",
                evidence="", references=("Monitoreo continuo",),
            ))
        return out
