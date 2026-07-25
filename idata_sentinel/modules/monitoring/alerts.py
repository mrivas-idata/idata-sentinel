"""Alertas del monitoreo continuo (plan maestro §6).

Se notifica cuando *cambia* el riesgo, no en cada escaneo: una alerta que llega
siempre deja de leerse. El envío nunca interrumpe el escaneo — un webhook caído
se registra y se sigue.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.modules.monitoring.diff import AssetsDiff, FindingsDiff

logger = logging.getLogger(__name__)

_ESCALATING = ("critical", "high")


@dataclass(frozen=True)
class Alert:
    level: str  # "critical" | "warning" | "info"
    title: str
    summary: str
    target: str
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "level": self.level, "title": self.title, "summary": self.summary,
            "target": self.target, "details": self.details,
        }


def build_alerts(
    *,
    target: str,
    findings_diff: FindingsDiff,
    assets_diff: AssetsDiff,
    trend: dict,
    expiring_certs: list[dict] | None = None,
) -> list[Alert]:
    alerts: list[Alert] = []

    severe = [f for f in findings_diff.new if f["severity"] in _ESCALATING]
    if severe:
        alerts.append(Alert(
            level="critical",
            title=f"{len(severe)} hallazgo(s) grave(s) nuevo(s) en {target}",
            summary="; ".join(f"[{f['severity'].upper()}] {f['title']}" for f in severe[:5]),
            target=target,
            details={"findings": [f["id"] for f in severe]},
        ))

    worsened = [c for c in findings_diff.severity_changes if c.worsened]
    if worsened:
        alerts.append(Alert(
            level="warning",
            title=f"{len(worsened)} hallazgo(s) empeoraron en {target}",
            summary="; ".join(f"{c.title}: {c.before} -> {c.after}" for c in worsened[:5]),
            target=target,
            details={"findings": [c.id for c in worsened]},
        ))

    if assets_diff.new_assets:
        alerts.append(Alert(
            level="warning",
            title=f"{len(assets_diff.new_assets)} activo(s) nuevo(s) en {target}",
            summary=", ".join(assets_diff.new_assets[:10]),
            target=target,
            details={"assets": assets_diff.new_assets},
        ))

    for cert in expiring_certs or []:
        alerts.append(Alert(
            level="warning",
            title=f"Certificado por vencer en {target}",
            summary=cert.get("finding", cert.get("title", "")),
            target=target,
            details={"finding_id": cert.get("id")},
        ))

    delta = trend.get("delta", 0)
    if delta <= -10:
        alerts.append(Alert(
            level="warning",
            title=f"El score de {target} cayó {abs(delta)} puntos",
            summary=f"{trend.get('previous')} -> {trend.get('current')}",
            target=target,
            details={"delta": delta},
        ))
    elif delta >= 10:
        alerts.append(Alert(
            level="info",
            title=f"El score de {target} mejoró {delta} puntos",
            summary=f"{trend.get('previous')} -> {trend.get('current')}",
            target=target,
            details={"delta": delta},
        ))

    return alerts


class Notifier(Protocol):
    async def send(self, alert: Alert) -> bool: ...


@dataclass
class WebhookNotifier:
    url: str
    http: HttpClient | None = None

    async def send(self, alert: Alert) -> bool:
        client = self.http or HttpClient()
        try:
            outcome = await client.post(self.url, json=alert.to_dict())
            return outcome.ok
        except Exception:  # una alerta fallida nunca rompe el escaneo
            logger.exception("no se pudo enviar la alerta a %s", self.url)
            return False


@dataclass
class CollectingNotifier:
    """Sink en memoria: útil para la CLI (imprimir al final) y para los tests."""

    sent: list[Alert] = field(default_factory=list)

    async def send(self, alert: Alert) -> bool:
        self.sent.append(alert)
        return True


async def dispatch(alerts: list[Alert], notifiers: list[Notifier]) -> int:
    delivered = 0
    for alert in alerts:
        for notifier in notifiers:
            if await notifier.send(alert):
                delivered += 1
    return delivered
