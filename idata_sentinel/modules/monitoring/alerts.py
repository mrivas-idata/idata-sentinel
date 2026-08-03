"""Alertas del monitoreo continuo (plan maestro §6).

Se notifica cuando *cambia* el riesgo, no en cada escaneo: una alerta que llega
siempre deja de leerse. El envío nunca interrumpe el escaneo — un webhook caído
se registra y se sigue.
"""
from __future__ import annotations

import asyncio
import logging
import os
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Protocol
from urllib.parse import urlparse

from idata_sentinel.core.http_client import HttpClient
from idata_sentinel.modules.monitoring.diff import AssetsDiff, FindingsDiff

logger = logging.getLogger(__name__)

_ESCALATING = ("critical", "high")
_LEVEL_RANK = {"critical": 0, "warning": 1, "info": 2}


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


# -- notificación por correo (digest) --------------------------------------


class DigestNotifier(Protocol):
    """Recibe **todas** las alertas de una corrida en un solo envío. El correo es
    un digest, no una alerta por mensaje: un cliente no quiere seis correos, quiere
    uno que diga 'esto cambió en tu sitio esta semana'."""

    async def send_digest(self, target: str, alerts: list[Alert], trend: dict | None) -> bool: ...


ENV_SMTP_HOST = "IDATA_SMTP_HOST"


@dataclass(frozen=True)
class EmailConfig:
    host: str
    port: int
    username: str
    password: str
    sender: str
    use_starttls: bool = True

    @classmethod
    def from_env(cls, env: dict | None = None) -> "EmailConfig | None":
        """Config SMTP desde el entorno, o `None` si no está configurada (en cuyo
        caso el correo simplemente no se envía). El envío es opt-in por diseño."""
        env = env if env is not None else os.environ
        host = (env.get(ENV_SMTP_HOST) or "").strip()
        if not host:
            return None
        return cls(
            host=host,
            port=int(env.get("IDATA_SMTP_PORT") or 587),
            username=(env.get("IDATA_SMTP_USER") or "").strip(),
            password=env.get("IDATA_SMTP_PASSWORD") or "",
            sender=(env.get("IDATA_SMTP_FROM") or env.get("IDATA_SMTP_USER") or "").strip(),
            use_starttls=(env.get("IDATA_SMTP_STARTTLS") or "true").lower() != "false",
        )


def build_digest(target: str, alerts: list[Alert], trend: dict | None) -> tuple[str, str, str]:
    """(asunto, texto plano, html) del digest de una corrida de monitoreo."""
    host = urlparse(target).hostname or target
    top = min((a.level for a in alerts), key=lambda lv: _LEVEL_RANK.get(lv, 3), default="info")
    prefix = "[CRÍTICO] " if top == "critical" else ""
    subject = f"{prefix}IDATA Sentinel — {len(alerts)} cambio(s) en {host}"

    trend = trend or {}
    delta = trend.get("delta", 0)
    trend_line = ""
    if delta:
        arrow = "▼" if delta < 0 else "▲"
        trend_line = f"Score de riesgo: {trend.get('previous')} → {trend.get('current')} ({arrow} {abs(delta)})"

    lines = [f"Cambios detectados en {host} desde el último escaneo:", ""]
    for a in alerts:
        lines.append(f"  • [{a.level.upper()}] {a.title}")
        if a.summary:
            lines.append(f"      {a.summary}")
    if trend_line:
        lines += ["", trend_line]
    lines += ["", "— IDATA Sentinel · idatachile.com"]
    text = "\n".join(lines)

    _color = {"critical": "#c0392b", "warning": "#d68910", "info": "#2471a3"}
    rows = "".join(
        f'<li style="margin-bottom:10px;"><span style="color:{_color.get(a.level, "#2471a3")};'
        f'font-weight:bold;">[{a.level.upper()}]</span> {_esc(a.title)}'
        + (f'<br><span style="color:#555;font-size:13px;">{_esc(a.summary)}</span>' if a.summary else "")
        + "</li>"
        for a in alerts
    )
    html = (
        f'<div style="font-family:Arial,sans-serif;max-width:600px;">'
        f'<h2 style="color:#1b2a4a;">Cambios en {_esc(host)}</h2>'
        f'<p style="color:#555;">Detectados desde el último escaneo de monitoreo.</p>'
        f'<ul style="list-style:none;padding:0;">{rows}</ul>'
        + (f'<p style="font-weight:bold;color:#1b2a4a;">{_esc(trend_line)}</p>' if trend_line else "")
        + '<hr style="border:none;border-top:1px solid #eee;">'
        '<p style="color:#888;font-size:12px;">IDATA Sentinel · '
        '<a href="https://idatachile.com">idatachile.com</a></p></div>'
    )
    return subject, text, html


def _esc(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@dataclass
class EmailNotifier:
    config: EmailConfig
    recipient: str
    #: Inyectable para test: función que envía el EmailMessage. Por defecto, SMTP real.
    sender_fn: "object | None" = None

    async def send_digest(self, target: str, alerts: list[Alert], trend: dict | None) -> bool:
        if not alerts:
            return True  # nada que reportar no es un fallo
        subject, text, html = build_digest(target, alerts, trend)
        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = self.config.sender
        message["To"] = self.recipient
        message.set_content(text)
        message.add_alternative(html, subtype="html")
        try:
            send = self.sender_fn or self._smtp_send
            await asyncio.to_thread(send, message)
            return True
        except Exception:  # un correo fallido nunca rompe el escaneo
            logger.exception("no se pudo enviar el digest de monitoreo a %s", self.recipient)
            return False

    def _smtp_send(self, message: EmailMessage) -> None:
        with smtplib.SMTP(self.config.host, self.config.port, timeout=30) as smtp:
            if self.config.use_starttls:
                smtp.starttls(context=ssl.create_default_context())
            if self.config.username:
                smtp.login(self.config.username, self.config.password)
            smtp.send_message(message)


async def dispatch(
    alerts: list[Alert], notifiers: list, *, target: str | None = None, trend: dict | None = None
) -> int:
    """Envía las alertas. Los notifiers por-alerta (webhook) reciben una llamada
    por alerta; los de digest (email) reciben todas juntas en un solo envío."""
    delivered = 0
    for notifier in notifiers:
        if hasattr(notifier, "send_digest"):
            if await notifier.send_digest(target or "", alerts, trend):
                delivered += 1
        else:
            for alert in alerts:
                if await notifier.send(alert):
                    delivered += 1
    return delivered
